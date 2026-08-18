"""Document surface — hidden prompts in files the agent is asked to read.

WHY THIS EXISTS
---------------
"Summarise this PDF" is the most common agent task in the enterprise, and the
document formats it targets were all designed to carry text a reader never sees:

  * DOCX keeps review comments, tracked deletions, headers/footers and core
    properties in separate XML parts that every text extractor concatenates.
  * PPTX keeps speaker notes in ``notesSlide*.xml`` — invisible on the slide,
    right there in the extraction.
  * PDF carries an /Info dictionary, annotations, and can render text in white,
    at 0pt, or outside the media box; it can also carry /JavaScript and
    /OpenAction, which are executable rather than textual.
  * XLSX/CSV hide payloads in far-off cells, defined names, and formulas.
  * Email carries HTML parts, headers an extractor happily reads, and
    attachments.

The uploader is frequently NOT the attacker: a user forwards a supplier invoice
or a candidate's CV in good faith. So the trust prior here is the same as the
browser surface — this is data, and data must not issue instructions.

THREAT MODEL
------------
  Attacker: authors a file that reaches the agent (emailed invoice, uploaded
            CV, shared deck, a document in an indexed drive).
  Goal:     have the extractor hand the model instructions the human sender and
            the human reader never saw.
  Defence:  format-aware extraction that KEEPS the channel (body vs comment vs
            metadata vs notes), then the data-channel prior from
            :mod:`app.surfaces.base`.

SELF-SECURITY
-------------
Parsing untrusted files is itself an attack surface, so this module treats every
input as hostile:
  * ZIP (OOXML) — entry-count, per-entry and total uncompressed-size caps, plus
    path-traversal rejection on entry names (zip-slip / zip-bomb).
  * XML — DOCTYPE and ENTITY declarations are rejected BEFORE parsing, which
    closes XXE, billion-laughs and quadratic-blowup without needing defusedxml.
  * PDF — decompression is bounded and every parse step is wrapped; a malformed
    file yields partial results and an alarm, never an exception escaping.

Pure stdlib: ``zipfile``, ``zlib``, ``csv``, ``email``, ``xml.etree``, ``json``.
No PDF/Office libraries required. Text-layer PDF extraction here is intentionally
simple (see :func:`_pdf_text`) — scanned/CID-encoded PDFs must be routed through
:mod:`app.surfaces.multimodal` OCR instead, and this module says so in its meta.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import zipfile
import zlib
from dataclasses import dataclass

from app.config import settings
from app.surfaces import base, browser
from app.surfaces.base import Segment, SurfaceFinding, SurfaceResult
from app.taxonomy import Channel, OwaspLLM, Verdict

_SURFACE = "documents"

# --- self-security caps for archive parsing --------------------------------
_MAX_ZIP_ENTRIES = 512
_MAX_ENTRY_BYTES = 8_000_000
_MAX_TOTAL_UNCOMPRESSED = 64_000_000
_MAX_XML_BYTES = 8_000_000


class DocumentParseError(Exception):
    """Raised when an artifact is malformed or trips a self-security cap."""


# ---------------------------------------------------------------------------
# Safe XML
# ---------------------------------------------------------------------------

_DOCTYPE_RE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_ENTITY_RE = re.compile(rb"<!ENTITY", re.IGNORECASE)


def safe_xml_parse(data: bytes):
    """Parse XML with XXE / entity-expansion classes refused up front.

    ``xml.etree.ElementTree`` does not resolve external entities, but it DOES
    expand internal ones, which is all "billion laughs" needs. Rejecting any
    document that declares a DTD or an entity costs us nothing (no legitimate
    OOXML part or config file declares one) and removes the whole class.
    """
    import xml.etree.ElementTree as ET

    if len(data) > _MAX_XML_BYTES:
        raise DocumentParseError(f"xml too large: {len(data)} bytes")
    head = data[:4096]
    if _DOCTYPE_RE.search(head) or _ENTITY_RE.search(data[:65536]):
        raise DocumentParseError("xml declares a DTD/ENTITY — refused (XXE/billion-laughs)")
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        raise DocumentParseError(f"malformed xml: {exc}") from exc


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


# ---------------------------------------------------------------------------
# Safe ZIP (OOXML container)
# ---------------------------------------------------------------------------

def _safe_zip_entries(data: bytes) -> dict[str, bytes]:
    """Read an OOXML container with zip-bomb and zip-slip protection."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as exc:
        raise DocumentParseError(f"not a readable zip container: {exc}") from exc

    infos = zf.infolist()
    if len(infos) > _MAX_ZIP_ENTRIES:
        raise DocumentParseError(f"zip has {len(infos)} entries (cap {_MAX_ZIP_ENTRIES})")

    total = sum(i.file_size for i in infos)
    if total > _MAX_TOTAL_UNCOMPRESSED:
        raise DocumentParseError(
            f"zip expands to {total} bytes (cap {_MAX_TOTAL_UNCOMPRESSED}) — bomb refused")

    out: dict[str, bytes] = {}
    for info in infos:
        name = info.filename
        # zip-slip: an entry that escapes the archive root.
        if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
            continue
        if info.file_size > _MAX_ENTRY_BYTES:
            continue
        if not name.lower().endswith((".xml", ".rels", ".txt")):
            continue  # we only read text parts; media goes to the multimodal surface
        try:
            out[name] = zf.read(info)
        except (zipfile.BadZipFile, OSError, RuntimeError):
            continue
    return out


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

@dataclass
class DetectedFormat:
    kind: str          # pdf | ooxml | html | xml | csv | json | email | text
    subtype: str = ""  # docx | pptx | xlsx | md | ...
    confidence: float = 1.0


def detect_format(data: bytes, filename: str = "", media_type: str = "") -> DetectedFormat:
    """Content-sniff first, filename second. Never trust the declared type alone."""
    ext = os.path.splitext(filename or "")[1].lower().lstrip(".")
    head = data[:2048]

    if head[:5] == b"%PDF-":
        return DetectedFormat("pdf")
    if head[:2] == b"PK" and (ext in {"docx", "pptx", "xlsx", "odt"} or b"[Content_Types]" in data[:4096]):
        sub = ext if ext in {"docx", "pptx", "xlsx"} else _ooxml_subtype(data)
        return DetectedFormat("ooxml", sub)
    stripped = head.lstrip()[:512].lower()
    if stripped[:9] == b"<!doctype" or stripped[:5] == b"<html" or b"<body" in head.lower():
        return DetectedFormat("html")
    if stripped[:5] == b"<?xml" or (stripped[:1] == b"<" and ext in {"xml", "svg", "rss"}):
        return DetectedFormat("xml", ext)
    if ext in {"eml", "msg"} or re.match(rb"(?im)^(from|to|subject|received|message-id):", head):
        return DetectedFormat("email")
    if ext == "csv" or ext == "tsv":
        return DetectedFormat("csv", ext)
    if ext == "json" or stripped[:1] in (b"{", b"["):
        return DetectedFormat("json")
    if ext in {"md", "markdown"}:
        return DetectedFormat("text", "md")
    if ext in {"yaml", "yml"}:
        return DetectedFormat("text", "yaml")
    return DetectedFormat("text", ext or "txt", confidence=0.5)


def _ooxml_subtype(data: bytes) -> str:
    try:
        names = set(_safe_zip_entries(data))
    except DocumentParseError:
        return "docx"
    if any(n.startswith("ppt/") for n in names):
        return "pptx"
    if any(n.startswith("xl/") for n in names):
        return "xlsx"
    return "docx"


# ---------------------------------------------------------------------------
# OOXML (DOCX / PPTX / XLSX)
# ---------------------------------------------------------------------------

# part-name pattern -> (channel, label). Order matters: first match wins.
_OOXML_PARTS: list[tuple[re.Pattern, Channel, str]] = [
    (re.compile(r"^word/comments\w*\.xml$"), Channel.COMMENT, "docx:comment"),
    (re.compile(r"^word/(header|footer)\d*\.xml$"), Channel.HIDDEN, "docx:header-footer"),
    (re.compile(r"^word/(foot|end)notes\.xml$"), Channel.COMMENT, "docx:note"),
    (re.compile(r"^word/document\d*\.xml$"), Channel.VISIBLE, "docx:body"),
    (re.compile(r"^ppt/notesSlides/.*\.xml$"), Channel.HIDDEN, "pptx:speaker-notes"),
    (re.compile(r"^ppt/comments?/.*\.xml$"), Channel.COMMENT, "pptx:comment"),
    (re.compile(r"^ppt/slides/slide\d+\.xml$"), Channel.VISIBLE, "pptx:slide"),
    (re.compile(r"^ppt/slideMasters/.*\.xml$"), Channel.HIDDEN, "pptx:master"),
    (re.compile(r"^xl/sharedStrings\.xml$"), Channel.STRUCTURED, "xlsx:strings"),
    (re.compile(r"^xl/comments\d*\.xml$"), Channel.COMMENT, "xlsx:comment"),
    (re.compile(r"^xl/worksheets/.*\.xml$"), Channel.STRUCTURED, "xlsx:sheet"),
    (re.compile(r"^docProps/(core|app|custom)\.xml$"), Channel.METADATA, "ooxml:properties"),
]


def _ooxml_segments(data: bytes) -> tuple[list[Segment], list[str]]:
    entries = _safe_zip_entries(data)
    segments: list[Segment] = []
    notes: list[str] = []

    for name in sorted(entries):
        channel, label = None, None
        for pattern, ch, lbl in _OOXML_PARTS:
            if pattern.match(name):
                channel, label = ch, lbl
                break
        if channel is None:
            continue
        try:
            root = safe_xml_parse(entries[name])
        except DocumentParseError as exc:
            notes.append(f"{name}: {exc}")
            continue

        # Tracked deletions (w:delText) are text the author REMOVED. A reader of
        # the final document never sees it; a naive extractor emits it.
        for el in root.iter():
            tag = _localname(el.tag)
            text = (el.text or "").strip()
            if not text:
                continue
            if tag in {"t", "delText", "instrText"}:
                ch = channel
                if tag == "delText":
                    ch = Channel.HIDDEN
                    label_x = f"{label}:tracked-deletion"
                elif tag == "instrText":
                    ch = Channel.CODE  # field codes, incl. DDE / hyperlink targets
                    label_x = f"{label}:field-code"
                else:
                    label_x = label
                segments.append(Segment(text=text, channel=ch, location=f"{label_x}:{name}"))
            elif channel == Channel.METADATA:
                segments.append(Segment(text=text, channel=Channel.METADATA,
                                        location=f"{label}:{tag}"))

    # Merge runs: OOXML splits a sentence across many <w:t> elements, which
    # would defeat every regex if scanned individually.
    return _merge_runs(segments), notes


def _merge_runs(segments: list[Segment]) -> list[Segment]:
    """Join consecutive segments sharing a channel+location into one block."""
    merged: list[Segment] = []
    for seg in segments:
        if (merged and merged[-1].channel == seg.channel
                and merged[-1].location == seg.location
                and len(merged[-1].text) < settings.surface_thresholds.max_segment_chars):
            merged[-1].text = f"{merged[-1].text} {seg.text}".strip()
        else:
            merged.append(seg)
    return merged


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

_PDF_STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
_PDF_INFO_KEYS = ("Title", "Author", "Subject", "Keywords", "Producer", "Creator")
# Active-content keys: these make a PDF executable rather than merely readable.
_PDF_ACTIVE = {
    b"/JavaScript": ("pdf-javascript", 0.70),
    b"/JS": ("pdf-javascript", 0.65),
    b"/OpenAction": ("pdf-openaction", 0.55),
    b"/AA": ("pdf-additional-action", 0.55),
    b"/Launch": ("pdf-launch-action", 0.80),
    b"/EmbeddedFile": ("pdf-embedded-file", 0.55),
    b"/SubmitForm": ("pdf-submit-form", 0.60),
}

_TJ_RE = re.compile(rb"\((?:\\.|[^\\()])*\)\s*Tj")
_TJ_ARRAY_RE = re.compile(rb"\[(.*?)\]\s*TJ", re.DOTALL)
_PDF_STRING_RE = re.compile(rb"\((?:\\.|[^\\()])*\)")


def _pdf_unescape(raw: bytes) -> str:
    body = raw[1:-1]  # strip the parentheses
    body = re.sub(rb"\\([nrtbf()\\])", lambda m: {
        b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f",
        b"(": b"(", b")": b")", b"\\": b"\\",
    }[m.group(1)], body)
    body = re.sub(rb"\\([0-7]{1,3})", lambda m: bytes([int(m.group(1), 8) & 0xFF]), body)
    return body.decode("utf-8", "replace")


def _pdf_text(data: bytes) -> list[str]:
    """Extract text-showing operators from (optionally Flate-compressed) streams.

    LIMITATION, stated plainly: this reads the text layer as literal bytes. PDFs
    using a CID font with a custom /ToUnicode CMap will decode to mojibake, and
    scanned PDFs have no text layer at all. Both cases are REPORTED in the
    result meta (``text_layer``) so the caller can route the file to OCR rather
    than silently believe an empty scan means a clean file.
    """
    chunks: list[str] = []
    budget = _MAX_TOTAL_UNCOMPRESSED

    for raw in _PDF_STREAM_RE.findall(data):
        if budget <= 0:
            break
        payload = raw
        if raw[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda", b"\x78\x5e"):
            try:
                d = zlib.decompressobj()
                payload = d.decompress(raw, _MAX_ENTRY_BYTES)
            except zlib.error:
                continue
        budget -= len(payload)

        text_parts: list[str] = []
        for m in _TJ_RE.finditer(payload):
            text_parts.append(_pdf_unescape(m.group(0).rsplit(b"Tj", 1)[0].strip()))
        for m in _TJ_ARRAY_RE.finditer(payload):
            joined = "".join(_pdf_unescape(s) for s in _PDF_STRING_RE.findall(m.group(1)))
            if joined.strip():
                text_parts.append(joined)
        if text_parts:
            chunks.append(" ".join(text_parts))
    return chunks


def _pdf_segments(data: bytes) -> tuple[list[Segment], list[tuple[str, float]], dict]:
    segments: list[Segment] = []
    findings: list[tuple[str, float]] = []

    # /Info metadata — read by extractors, invisible in the rendered page.
    for key in _PDF_INFO_KEYS:
        for m in re.finditer(rb"/" + key.encode() + rb"\s*(\((?:\\.|[^\\()])*\))", data):
            value = _pdf_unescape(m.group(1)).strip()
            if value:
                segments.append(Segment(text=value, channel=Channel.METADATA,
                                        location=f"pdf:/Info:/{key}"))

    # Annotations (/Contents on an annot) — sticky notes, form tooltips.
    for m in re.finditer(rb"/Subtype\s*/(Text|FreeText|Popup|Widget)[^>]{0,400}?"
                         rb"/Contents\s*(\((?:\\.|[^\\()])*\))", data, re.DOTALL):
        value = _pdf_unescape(m.group(2)).strip()
        if value:
            segments.append(Segment(text=value, channel=Channel.COMMENT,
                                    location=f"pdf:annot:{m.group(1).decode()}"))

    seen_active: dict[str, float] = {}
    for marker, (kind, severity) in _PDF_ACTIVE.items():
        if marker in data:
            seen_active[kind] = max(seen_active.get(kind, 0.0), severity)
    findings.extend(sorted(seen_active.items(), key=lambda kv: -kv[1]))

    body = _pdf_text(data)
    for i, chunk in enumerate(body):
        segments.append(Segment(text=chunk, channel=Channel.VISIBLE,
                                location=f"pdf:content-stream[{i}]"))

    meta = {
        "text_layer": "present" if body else "absent",
        "streams": len(_PDF_STREAM_RE.findall(data)),
        "note": ("no extractable text layer — route to OCR (multimodal surface) "
                 "before trusting a clean verdict" if not body else ""),
    }
    return segments, findings, meta


# ---------------------------------------------------------------------------
# Text-ish formats
# ---------------------------------------------------------------------------

_MD_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_MD_FENCE_RE = re.compile(r"```[\w-]*\n(.*?)```", re.DOTALL)
_MD_LINK_RE = re.compile(r"!?\[([^\]]{0,120})\]\(([^)\s]{0,400})\)")
_MD_REF_RE = re.compile(r"(?m)^\s{0,3}\[([^\]]{1,60})\]:\s*(\S{1,400})")


def _markdown_segments(text: str) -> list[Segment]:
    """Markdown hides text in comments, link titles, and reference definitions.

    Markdown is the agent-ecosystem lingua franca (READMEs, tool descriptions,
    wiki pages, MCP manifests), and ``<!-- -->`` survives every renderer while
    remaining invisible to the human reviewing the diff.
    """
    segments: list[Segment] = []
    body = text

    for i, m in enumerate(_MD_COMMENT_RE.finditer(text)):
        segments.append(Segment(text=m.group(1), channel=Channel.COMMENT,
                                location=f"md:comment[{i}]"))
    body = _MD_COMMENT_RE.sub(" ", body)

    for i, m in enumerate(_MD_FENCE_RE.finditer(text)):
        segments.append(Segment(text=m.group(1), channel=Channel.CODE,
                                location=f"md:code-fence[{i}]"))
    body = _MD_FENCE_RE.sub(" ", body)

    for i, m in enumerate(_MD_LINK_RE.finditer(text)):
        target = m.group(2)
        if target.lower().startswith(("javascript:", "data:")) or re.search(r"[?&]\w+=", target):
            segments.append(Segment(text=target, channel=Channel.CODE,
                                    location=f"md:link-target[{i}]"))
    for i, m in enumerate(_MD_REF_RE.finditer(text)):
        segments.append(Segment(text=m.group(2), channel=Channel.ATTRIBUTE,
                                location=f"md:link-ref[{i}]"))

    if body.strip():
        segments.append(Segment(text=body, channel=Channel.VISIBLE, location="md:body"))
    return segments


# A leading =, +, -, or @ makes a cell a FORMULA when the file is opened in a
# spreadsheet, and DDE/command execution is reachable from there. The dangerous
# functions are the ones that reach outside the sheet.
_CSV_FORMULA_START = re.compile(r"^[=+\-@\t\r]")
_CSV_DANGEROUS_FN = re.compile(
    r"\b(cmd\s*\||DDE|WEBSERVICE|IMPORTXML|IMPORTDATA|IMPORTFEED|IMPORTHTML|"
    r"HYPERLINK|EXEC|SHELL|MSEXCEL|rundll32|powershell)\b|\|\s*'?\s*(cmd|/c)",
    re.IGNORECASE)


def _csv_segments(text: str, delimiter: str = ",") -> tuple[list[Segment], list[tuple[str, float]]]:
    segments: list[Segment] = []
    findings: list[tuple[str, float]] = []
    try:
        reader = csv.reader(io.StringIO(text), delimiter=delimiter)
        rows = list(reader)
    except (csv.Error, ValueError):
        return ([Segment(text=text, channel=Channel.STRUCTURED, location="csv:raw")],
                findings)

    formula_cells = 0
    for r, row in enumerate(rows[: settings.surface_thresholds.max_segments]):
        for c, cell in enumerate(row):
            cell = (cell or "").strip()
            if not cell:
                continue
            is_formula = bool(_CSV_FORMULA_START.match(cell))
            channel = Channel.CODE if is_formula else Channel.STRUCTURED
            if is_formula:
                formula_cells += 1
                if _CSV_DANGEROUS_FN.search(cell):
                    findings.append((f"csv-formula-injection:r{r}c{c}", 0.80))
            segments.append(Segment(text=cell, channel=channel,
                                    location=f"csv:r{r}c{c}"))
    if formula_cells and not findings:
        # Formulas in data an agent was asked to read are worth reporting even
        # when the function itself is inert — the file is not plain data.
        findings.append((f"csv-formula-cells:{formula_cells}", 0.40))
    return segments, findings


def _xml_segments(data: bytes) -> list[Segment]:
    root = safe_xml_parse(data)
    segments: list[Segment] = []
    for el in root.iter():
        path = _localname(el.tag)
        if (el.text or "").strip():
            segments.append(Segment(text=el.text.strip(), channel=Channel.STRUCTURED,
                                    location=f"xml:{path}"))
        for key, value in (el.attrib or {}).items():
            if (value or "").strip():
                segments.append(Segment(text=value.strip(), channel=Channel.ATTRIBUTE,
                                        location=f"xml:{path}@{_localname(key)}"))
    # ElementTree drops comments; recover them directly so the channel survives.
    for i, m in enumerate(re.finditer(rb"<!--(.*?)-->", data, re.DOTALL)):
        segments.append(Segment(text=m.group(1).decode("utf-8", "replace"),
                                channel=Channel.COMMENT, location=f"xml:comment[{i}]"))
    return segments


def _json_segments(text: str) -> list[Segment]:
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return [Segment(text=text, channel=Channel.STRUCTURED, location="json:raw")]

    segments: list[Segment] = []

    def walk(node, path: str, depth: int = 0) -> None:
        if depth > 20 or len(segments) >= settings.surface_thresholds.max_segments:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                # Keys are attacker-controlled too — a key named
                # "system_instructions" is itself the injection.
                if isinstance(k, str) and len(k) > 40:
                    segments.append(Segment(text=k, channel=Channel.STRUCTURED,
                                            location=f"{path}.<key>"))
                walk(v, f"{path}.{k}", depth + 1)
        elif isinstance(node, list):
            for i, v in enumerate(node[:200]):
                walk(v, f"{path}[{i}]", depth + 1)
        elif isinstance(node, str) and node.strip():
            segments.append(Segment(text=node, channel=Channel.STRUCTURED, location=path))

    walk(doc, "json")
    return segments


def _email_segments(data: bytes) -> tuple[list[Segment], list[str]]:
    """RFC822: headers are a channel, and HTML parts recurse into the browser
    surface so an emailed page gets full CSS-visibility analysis."""
    from email import policy
    from email.parser import BytesParser

    notes: list[str] = []
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:  # noqa: BLE001 — malformed mail is common
        raise DocumentParseError(f"unparseable email: {exc}") from exc

    segments: list[Segment] = []
    for header in ("Subject", "From", "To", "Cc", "Reply-To", "X-Mailer"):
        value = msg.get(header)
        if value:
            segments.append(Segment(text=str(value), channel=Channel.METADATA,
                                    location=f"email:header:{header}"))
    # Non-standard X- headers are a favourite smuggling channel.
    for key, value in msg.items():
        if key.lower().startswith("x-") and key.lower() != "x-mailer" and value:
            segments.append(Segment(text=str(value), channel=Channel.METADATA,
                                    location=f"email:header:{key}"))

    for i, part in enumerate(msg.walk()):
        ctype = part.get_content_type()
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "")
        if disposition == "attachment":
            name = part.get_filename() or f"attachment[{i}]"
            segments.append(Segment(text=str(name), channel=Channel.METADATA,
                                    location=f"email:attachment-name[{i}]"))
            notes.append(f"attachment not recursed: {name} ({ctype})")
            continue
        try:
            payload = part.get_content()
        except (LookupError, ValueError):
            continue
        if not isinstance(payload, str) or not payload.strip():
            continue
        if ctype == "text/html":
            html_segments, _ = browser.extract(payload)
            for seg in html_segments:
                seg.location = f"email:part[{i}]>{seg.location}"
                segments.append(seg)
        else:
            segments.append(Segment(text=payload, channel=Channel.VISIBLE,
                                    location=f"email:part[{i}]:{ctype}"))
    return segments, notes


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_segments(data: bytes | str, *, filename: str = "",
                     media_type: str = "") -> tuple[list[Segment], dict]:
    """Format-detect and extract channel-tagged segments. Raises DocumentParseError."""
    raw = data.encode("utf-8", "replace") if isinstance(data, str) else (data or b"")
    fmt = detect_format(raw, filename, media_type)
    meta: dict = {"format": fmt.kind, "subtype": fmt.subtype, "bytes": len(raw),
                  "filename": filename, "parse_notes": []}

    if fmt.kind == "pdf":
        segments, active, pdf_meta = _pdf_segments(raw)
        meta.update(pdf_meta)
        meta["active_content"] = [k for k, _ in active]
        meta["_active_findings"] = active
        return segments, meta

    if fmt.kind == "ooxml":
        segments, notes = _ooxml_segments(raw)
        meta["parse_notes"] = notes
        return segments, meta

    if fmt.kind == "email":
        segments, notes = _email_segments(raw)
        meta["parse_notes"] = notes
        return segments, meta

    if fmt.kind == "xml":
        return _xml_segments(raw), meta

    text = raw.decode("utf-8", "replace")

    if fmt.kind == "html":
        segments, notes = browser.extract(text)
        meta["parse_notes"] = [n[0] for n in notes]
        return segments, meta
    if fmt.kind == "csv":
        segments, csv_findings = _csv_segments(
            text, "\t" if fmt.subtype == "tsv" else ",")
        meta["_active_findings"] = csv_findings
        return segments, meta
    if fmt.kind == "json":
        return _json_segments(text), meta
    if fmt.subtype == "md":
        return _markdown_segments(text), meta

    return [Segment(text=text, channel=Channel.VISIBLE, location="text:body")], meta


def scan(data: bytes | str, *, filename: str = "", media_type: str = "",
         source: str = "") -> SurfaceResult:
    """Scan an uploaded or retrieved document for embedded instructions.

    ``sanitized`` is the document reduced to its visible body text, with every
    comment, note, metadata, and hidden-channel segment removed.
    """
    if not settings.surfaces.enabled("documents"):
        payload = data if isinstance(data, str) else ""
        return base.disabled(_SURFACE, passthrough=payload)

    th = settings.surface_thresholds
    raw = data.encode("utf-8", "replace") if isinstance(data, str) else (data or b"")
    if len(raw) > th.max_artifact_bytes:
        return SurfaceResult(
            surface=_SURFACE, verdict=Verdict.BLOCK, risk=1.0,
            reasons=[f"artifact-too-large:{len(raw)}>{th.max_artifact_bytes}"],
            quarantined=True, category=OwaspLLM.LLM10_UNBOUNDED_CONSUMPTION,
            meta={"filename": filename},
        )

    try:
        segments, meta = extract_segments(raw, filename=filename, media_type=media_type)
    except DocumentParseError as exc:
        # A file we cannot parse is a file we cannot clear. Fail closed: the
        # caller gets REVIEW with an explicit reason, never a silent ALLOW.
        return SurfaceResult(
            surface=_SURFACE, verdict=Verdict.REVIEW, risk=th.quarantine,
            quarantined=True, reasons=[f"parse-refused:{exc}"],
            category=OwaspLLM.LLM03_SUPPLY_CHAIN,
            meta={"filename": filename, "error": str(exc)},
        )

    for seg in segments:
        seg.source = source or filename or meta.get("format", "document")

    result = base.scan_segments(segments, surface=_SURFACE, thresholds=th,
                                strip_invisible=True)

    # Structural findings describe the FILE itself (PDF active content, CSV
    # formula cells) rather than any text segment inside it.
    for kind, severity in meta.pop("_active_findings", []):
        result.findings.append(SurfaceFinding(
            surface=_SURFACE, location=f"{meta.get('format', 'document')}:structure",
            channel=Channel.CODE.value, severity=severity, kind=kind,
            reason=f"file carries active content ({kind})",
            category=OwaspLLM.LLM03_SUPPLY_CHAIN, source=source or filename,
        ))
        result.risk = max(result.risk, severity)
        result.reasons.append(kind)
    if result.risk >= th.block and result.verdict != Verdict.BLOCK:
        result.verdict = Verdict.BLOCK
        result.quarantined = True

    result.meta.update(meta)
    result.meta["channels"] = _channel_histogram(segments)
    return result


def _channel_histogram(segments: list[Segment]) -> dict[str, int]:
    hist: dict[str, int] = {}
    for s in segments:
        hist[s.channel.value] = hist.get(s.channel.value, 0) + 1
    return hist
