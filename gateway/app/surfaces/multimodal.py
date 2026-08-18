"""Multimodal surface — image and audio side channels (LLM01 indirect).

WHY THIS EXISTS
---------------
A vision model reads text in a picture. That single fact reopens every injection
vector the text pipeline just closed, with none of the defences, because the
payload never exists as a string in the request: it is pixels that say "ignore
your instructions" in 6pt grey on a white wall, or a QR code in the corner of a
slide, or a caption rendered outside the crop a human reviewer saw.

There are two distinct channels here, and it matters that they are separated:

  1. METADATA — EXIF, PNG text chunks, GIF comments, XMP packets, ID3 tags.
     This is real text, in the file, extractable with the standard library, and
     routinely concatenated into prompts by captioning and asset pipelines. It
     is fully analysable offline and it is where this module does its work.
  2. RENDERED CONTENT — text that only exists once the image is decoded, or
     speech that only exists once the audio is transcribed. Reading that
     requires OCR/ASR, which requires models this project deliberately does not
     ship (see the offline-first posture in ``docs/ARCHITECTURE.md``).

HONESTY ABOUT COVERAGE
----------------------
This module does NOT perform OCR, decode QR codes, or transcribe audio, and it
does not pretend to. Instead it:
  * fully scans every metadata channel it can reach with stdlib;
  * detects structural anomalies (polyglot files, appended archives, oversized
    metadata) that indicate a file is carrying more than an image;
  * exposes provider hooks (:func:`register_ocr`, :func:`register_transcriber`)
    so a deployment that HAS an OCR/ASR stack routes the recovered text back
    through the same instruction-in-data engine as everything else;
  * reports ``coverage`` in its result, so a clean verdict on an un-OCR'd image
    reads as "not analysed" rather than "safe".

That last point is the security-relevant one. A firewall that silently returns
ALLOW for content it cannot inspect teaches operators to trust a signal that
means nothing.

THREAT MODEL
------------
  Attacker: supplies an image or audio file to a multimodal agent.
  Goals:    instructions via EXIF/XMP/text chunks (works today against most
            captioning pipelines); instructions rendered in pixels; a QR code
            pointing at an injection page; a polyglot file that is both a valid
            PNG and a valid ZIP/HTML.
  Defence:  extract and scan every reachable channel, flag structural
            anomalies, and be explicit about what was not inspected.
"""
from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass, field
from typing import Callable

from app.config import settings
from app.surfaces import base
from app.surfaces.base import Segment, SurfaceFinding, SurfaceResult
from app.taxonomy import Channel, OwaspLLM, Verdict

_SURFACE = "multimodal"

_MAX_METADATA_FIELD = 16_000


@dataclass
class MediaResult(SurfaceResult):
    """SurfaceResult plus explicit coverage reporting."""

    media_type: str = ""
    coverage: dict = field(default_factory=dict)   # channel -> analysed | not-analysed

    def as_dict(self) -> dict:
        d = super().as_dict()
        d.update({"media_type": self.media_type, "coverage": self.coverage})
        return d


# ---------------------------------------------------------------------------
# Pluggable OCR / ASR providers
# ---------------------------------------------------------------------------

_ocr_provider: Callable[[bytes], str] | None = None
_transcriber: Callable[[bytes], str] | None = None
_qr_provider: Callable[[bytes], list[str]] | None = None


def register_ocr(fn: Callable[[bytes], str] | None) -> None:
    """Install an OCR provider: ``bytes -> extracted text``.

    Whatever it returns is treated as fully untrusted data and scanned by the
    same engine as documents and web pages. Pass None to uninstall.
    """
    global _ocr_provider
    _ocr_provider = fn


def register_transcriber(fn: Callable[[bytes], str] | None) -> None:
    """Install a speech-to-text provider: ``bytes -> transcript``."""
    global _transcriber
    _transcriber = fn


def register_qr_decoder(fn: Callable[[bytes], list[str]] | None) -> None:
    """Install a QR/barcode decoder: ``bytes -> list of decoded payloads``."""
    global _qr_provider
    _qr_provider = fn


def providers() -> dict[str, bool]:
    return {"ocr": _ocr_provider is not None,
            "transcriber": _transcriber is not None,
            "qr": _qr_provider is not None}


# ---------------------------------------------------------------------------
# Format sniffing
# ---------------------------------------------------------------------------

_MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "image/webp"),        # refined below
    (b"BM", "image/bmp"),
    (b"II*\x00", "image/tiff"),
    (b"MM\x00*", "image/tiff"),
    (b"ID3", "audio/mpeg"),
    (b"OggS", "audio/ogg"),
    (b"fLaC", "audio/flac"),
]


def sniff(data: bytes) -> str:
    head = data[:16]
    for magic, mime in _MAGIC:
        if head.startswith(magic):
            if mime == "image/webp":
                return "image/webp" if data[8:12] == b"WEBP" else "audio/wav"
            return mime
    if head[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return "audio/wav"
    if data[4:12] in (b"ftypmp42", b"ftypisom", b"ftypM4A ", b"ftypmp41"):
        return "video/mp4"
    stripped = data.lstrip()[:200].lower()
    if stripped.startswith(b"<svg") or (stripped.startswith(b"<?xml") and b"<svg" in data[:2048].lower()):
        return "image/svg+xml"
    return "application/octet-stream"


# ---------------------------------------------------------------------------
# PNG
# ---------------------------------------------------------------------------

def _png_chunks(data: bytes) -> list[tuple[str, bytes]]:
    """Iterate PNG chunks defensively (length fields are attacker-controlled)."""
    out: list[tuple[str, bytes]] = []
    pos = 8
    while pos + 12 <= len(data) and len(out) < 512:
        try:
            (length,) = struct.unpack(">I", data[pos:pos + 4])
        except struct.error:
            break
        ctype = data[pos + 4:pos + 8].decode("ascii", "replace")
        if length > len(data):
            break
        payload = data[pos + 8:pos + 8 + length]
        out.append((ctype, payload))
        pos += 12 + length
        if ctype == "IEND":
            break
    return out


def _png_segments(data: bytes) -> tuple[list[Segment], list[tuple[str, float, str]]]:
    segments: list[Segment] = []
    notes: list[tuple[str, float, str]] = []
    end_offset = None

    for i, (ctype, payload) in enumerate(_png_chunks(data)):
        if ctype == "IEND":
            end_offset = data.find(b"IEND")
        text = ""
        if ctype == "tEXt":
            key, _, value = payload.partition(b"\x00")
            text = f"{key.decode('latin-1', 'replace')}: {value.decode('latin-1', 'replace')}"
        elif ctype == "iTXt":
            parts = payload.split(b"\x00", 5)
            if len(parts) >= 6:
                key = parts[0].decode("utf-8", "replace")
                body = parts[5]
                if parts[1:2] == b"\x01":  # compressed
                    try:
                        body = zlib.decompress(body)
                    except zlib.error:
                        body = b""
                text = f"{key}: {body.decode('utf-8', 'replace')}"
        elif ctype == "zTXt":
            key, _, comp = payload.partition(b"\x00")
            try:
                text = (f"{key.decode('latin-1', 'replace')}: "
                        f"{zlib.decompress(comp[1:]).decode('utf-8', 'replace')}")
            except zlib.error:
                text = ""
        elif ctype in {"eXIf", "iCCP"}:
            text = _printable_runs(payload)

        if text.strip():
            segments.append(Segment(text=text[:_MAX_METADATA_FIELD],
                                    channel=Channel.METADATA,
                                    location=f"png:{ctype}[{i}]"))

    # Data appended after IEND: the file is a polyglot or a carrier.
    if end_offset is not None:
        tail_start = end_offset + 8
        tail = data[tail_start:]
        if len(tail) > 64:
            notes.append(("appended-data-after-iend", 0.70,
                          f"{len(tail)} bytes after IEND"))
            if tail[:2] == b"PK":
                notes.append(("polyglot-zip-in-png", 0.85, "ZIP archive appended"))
            if re.search(rb"<\?php|<script|<html", tail[:4096], re.IGNORECASE):
                notes.append(("polyglot-markup-in-png", 0.80, "markup appended"))
            segments.append(Segment(text=_printable_runs(tail[:_MAX_METADATA_FIELD]),
                                    channel=Channel.HIDDEN, location="png:trailing-data"))
    return segments, notes


# ---------------------------------------------------------------------------
# JPEG
# ---------------------------------------------------------------------------

def _jpeg_segments(data: bytes) -> tuple[list[Segment], list[tuple[str, float, str]]]:
    segments: list[Segment] = []
    notes: list[tuple[str, float, str]] = []
    pos = 2
    count = 0
    while pos + 4 <= len(data) and count < 256:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1        # fill byte — the spec allows runs of them
            continue
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xDA:  # start of scan — image data follows
            break
        try:
            (seg_len,) = struct.unpack(">H", data[pos + 2:pos + 4])
        except struct.error:
            break
        payload = data[pos + 4:pos + 2 + seg_len]
        count += 1

        if marker == 0xFE:  # COM
            segments.append(Segment(text=payload.decode("utf-8", "replace")[:_MAX_METADATA_FIELD],
                                    channel=Channel.COMMENT, location=f"jpeg:COM[{count}]"))
        elif marker == 0xE1:  # APP1: EXIF or XMP
            if payload[:6] == b"Exif\x00\x00":
                text = _printable_runs(payload[6:])
                if text.strip():
                    segments.append(Segment(text=text[:_MAX_METADATA_FIELD],
                                            channel=Channel.METADATA,
                                            location=f"jpeg:EXIF[{count}]"))
            elif b"xmpmeta" in payload[:200] or payload[:29].startswith(b"http://ns.adobe.com/xap/"):
                segments.append(Segment(text=payload.decode("utf-8", "replace")[:_MAX_METADATA_FIELD],
                                        channel=Channel.METADATA,
                                        location=f"jpeg:XMP[{count}]"))
        elif 0xE0 <= marker <= 0xEF:  # other APPn
            text = _printable_runs(payload)
            if len(text.strip()) > 20:
                segments.append(Segment(text=text[:_MAX_METADATA_FIELD],
                                        channel=Channel.METADATA,
                                        location=f"jpeg:APP{marker - 0xE0}[{count}]"))
        pos += 2 + seg_len

    tail = data.rsplit(b"\xff\xd9", 1)
    if len(tail) == 2 and len(tail[1]) > 64:
        notes.append(("appended-data-after-eoi", 0.70, f"{len(tail[1])} bytes after EOI"))
        if tail[1][:2] == b"PK":
            notes.append(("polyglot-zip-in-jpeg", 0.85, "ZIP archive appended"))
        segments.append(Segment(text=_printable_runs(tail[1][:_MAX_METADATA_FIELD]),
                                channel=Channel.HIDDEN, location="jpeg:trailing-data"))
    return segments, notes


# ---------------------------------------------------------------------------
# GIF / WebP / audio containers
# ---------------------------------------------------------------------------

def _gif_segments(data: bytes) -> list[Segment]:
    segments: list[Segment] = []
    for i, m in enumerate(re.finditer(rb"\x21\xfe(.*?)\x00", data[:1_000_000], re.DOTALL)):
        text = _printable_runs(m.group(1))
        if len(text.strip()) > 3:
            segments.append(Segment(text=text[:_MAX_METADATA_FIELD],
                                    channel=Channel.COMMENT, location=f"gif:comment[{i}]"))
    return segments


def _riff_segments(data: bytes) -> list[Segment]:
    """WebP/WAV: walk RIFF chunks and pull the text-bearing ones."""
    segments: list[Segment] = []
    pos = 12
    i = 0
    while pos + 8 <= len(data) and i < 256:
        fourcc = data[pos:pos + 4].decode("ascii", "replace")
        try:
            (size,) = struct.unpack("<I", data[pos + 4:pos + 8])
        except struct.error:
            break
        if size > len(data):
            break
        payload = data[pos + 8:pos + 8 + size]
        if fourcc.strip() in {"EXIF", "XMP", "LIST", "ICMT", "INFO", "ISFT", "ICOP"}:
            text = _printable_runs(payload)
            if len(text.strip()) > 8:
                segments.append(Segment(text=text[:_MAX_METADATA_FIELD],
                                        channel=Channel.METADATA,
                                        location=f"riff:{fourcc.strip()}[{i}]"))
        pos += 8 + size + (size % 2)
        i += 1
    return segments


def _id3_segments(data: bytes) -> list[Segment]:
    """ID3v2 frames — an mp3 handed to an ASR pipeline carries text before a
    single sample is decoded, and comment/lyrics frames are unbounded."""
    segments: list[Segment] = []
    if data[:3] != b"ID3" or len(data) < 10:
        return segments
    size = 0
    for b in data[6:10]:
        size = (size << 7) | (b & 0x7F)   # synchsafe integer
    body = data[10:10 + min(size, len(data))]
    pos = 0
    i = 0
    while pos + 10 <= len(body) and i < 256:
        frame_id = body[pos:pos + 4].decode("ascii", "replace")
        if not frame_id.strip() or not frame_id[0].isalpha():
            break
        try:
            (fsize,) = struct.unpack(">I", body[pos + 4:pos + 8])
        except struct.error:
            break
        if fsize <= 0 or fsize > len(body):
            break
        payload = body[pos + 10:pos + 10 + fsize]
        if frame_id.startswith(("T", "COMM", "USLT", "WXXX")):
            text = _printable_runs(payload)
            if len(text.strip()) > 3:
                segments.append(Segment(text=text[:_MAX_METADATA_FIELD],
                                        channel=Channel.METADATA,
                                        location=f"id3:{frame_id}[{i}]"))
        pos += 10 + fsize
        i += 1
    return segments


_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e][\x20-\x7e\t]{3,}")


def _printable_runs(blob: bytes, min_len: int = 4) -> str:
    """Recover ASCII strings from a binary metadata blob.

    EXIF is a nested TIFF structure; rather than implement a full IFD walker
    (which would itself be an attack surface), pull printable runs. That is
    strictly more inclusive than tag-aware parsing, which is the safe direction
    here — we would rather scan a byte run that turns out to be binary than miss
    a payload in a tag we did not model.
    """
    parts = [m.group(0).decode("latin-1", "replace")
             for m in _PRINTABLE_RUN.finditer(blob or b"")]
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Structural anomalies
# ---------------------------------------------------------------------------

def _structural_notes(data: bytes, mime: str,
                      segments: list[Segment]) -> list[tuple[str, float, str]]:
    notes: list[tuple[str, float, str]] = []
    meta_bytes = sum(len(s.text) for s in segments)
    if data and meta_bytes > max(8192, len(data) * 0.35):
        # Metadata dwarfing the payload is a carrier, not a photograph.
        notes.append(("metadata-dominates-payload", 0.55,
                      f"{meta_bytes} metadata chars vs {len(data)} file bytes"))
    if mime.startswith("image/") and b"<script" in data[:200_000].lower():
        notes.append(("script-in-image", 0.75, "<script> found in image bytes"))
    return notes


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def scan(data: bytes, *, filename: str = "", media_type: str = "",
         ocr_text: str = "", transcript: str = "") -> MediaResult:
    """Scan an image or audio artifact.

    ``ocr_text`` / ``transcript`` let a caller that already ran OCR or ASR feed
    the recovered text in directly; otherwise a registered provider is used, and
    if neither exists the result records that channel as ``not-analysed``.
    """
    if not settings.surfaces.enabled("multimodal"):
        return MediaResult(surface=_SURFACE, enabled=False,
                           reasons=[f"surface-disabled:{_SURFACE}"])

    th = settings.surface_thresholds
    raw = data or b""
    if len(raw) > th.max_artifact_bytes:
        return MediaResult(
            surface=_SURFACE, verdict=Verdict.BLOCK, risk=1.0, quarantined=True,
            reasons=[f"artifact-too-large:{len(raw)}>{th.max_artifact_bytes}"],
            category=OwaspLLM.LLM10_UNBOUNDED_CONSUMPTION, media_type=media_type,
        )

    mime = media_type or sniff(raw)
    segments: list[Segment] = []
    notes: list[tuple[str, float, str]] = []
    coverage: dict[str, str] = {}

    if mime == "image/png":
        segs, n = _png_segments(raw)
        segments += segs
        notes += n
        coverage["metadata"] = "analysed"
    elif mime == "image/jpeg":
        segs, n = _jpeg_segments(raw)
        segments += segs
        notes += n
        coverage["metadata"] = "analysed"
    elif mime == "image/gif":
        segments += _gif_segments(raw)
        coverage["metadata"] = "analysed"
    elif mime in {"image/webp", "audio/wav"}:
        segments += _riff_segments(raw)
        coverage["metadata"] = "analysed"
    elif mime == "audio/mpeg":
        segments += _id3_segments(raw)
        coverage["metadata"] = "analysed"
    elif mime == "image/svg+xml":
        # SVG is markup, not pixels: it can carry scripts, foreignObject HTML,
        # and text nodes. Route it through the browser surface, which already
        # understands hidden-versus-visible.
        from app.surfaces import browser
        svg_segments, _ = browser.extract(raw.decode("utf-8", "replace"))
        segments += svg_segments
        coverage["markup"] = "analysed"
    else:
        # Unknown container: printable-run scan is better than nothing, and the
        # coverage map says plainly that this was a fallback.
        text = _printable_runs(raw[:1_000_000])
        if text.strip():
            segments.append(Segment(text=text[:_MAX_METADATA_FIELD],
                                    channel=Channel.METADATA,
                                    location=f"{mime}:printable-runs"))
        coverage["metadata"] = "partial-fallback-scan"

    notes += _structural_notes(raw, mime, segments)

    # --- rendered-content channels ------------------------------------------
    text_from_pixels = ocr_text
    if not text_from_pixels and _ocr_provider is not None and mime.startswith("image/"):
        try:
            text_from_pixels = _ocr_provider(raw) or ""
        except Exception as exc:  # noqa: BLE001 — a provider must not break the scan
            notes.append(("ocr-provider-error", 0.30, type(exc).__name__))
            text_from_pixels = ""
    if mime.startswith("image/"):
        coverage["rendered_text"] = "analysed" if text_from_pixels else (
            "not-analysed:no-ocr-provider" if _ocr_provider is None else "empty")
    if text_from_pixels:
        segments.append(Segment(text=text_from_pixels, channel=Channel.HIDDEN,
                                location="image:ocr"))

    spoken = transcript
    if not spoken and _transcriber is not None and mime.startswith(("audio/", "video/")):
        try:
            spoken = _transcriber(raw) or ""
        except Exception as exc:  # noqa: BLE001
            notes.append(("asr-provider-error", 0.30, type(exc).__name__))
            spoken = ""
    if mime.startswith(("audio/", "video/")):
        coverage["speech"] = "analysed" if spoken else (
            "not-analysed:no-transcriber" if _transcriber is None else "empty")
    if spoken:
        segments.append(Segment(text=spoken, channel=Channel.HIDDEN,
                                location="audio:transcript"))

    if _qr_provider is not None and mime.startswith("image/"):
        try:
            for i, payload in enumerate(_qr_provider(raw) or []):
                segments.append(Segment(text=payload, channel=Channel.CODE,
                                        location=f"image:qr[{i}]"))
            coverage["barcodes"] = "analysed"
        except Exception as exc:  # noqa: BLE001
            notes.append(("qr-provider-error", 0.30, type(exc).__name__))
            coverage["barcodes"] = "provider-error"
    elif mime.startswith("image/"):
        coverage["barcodes"] = "not-analysed:no-decoder"

    for seg in segments:
        seg.source = filename or mime

    scanned = base.scan_segments(segments, surface=_SURFACE, thresholds=th,
                                 strip_invisible=False)

    result = MediaResult(
        surface=_SURFACE, verdict=scanned.verdict, risk=scanned.risk,
        category=scanned.category, findings=scanned.findings,
        sanitized=scanned.sanitized, segments_scanned=scanned.segments_scanned,
        segments_removed=scanned.segments_removed, quarantined=scanned.quarantined,
        latency_ms=scanned.latency_ms, reasons=list(scanned.reasons),
        media_type=mime, coverage=coverage,
    )

    for kind, severity, excerpt in notes:
        result.findings.append(SurfaceFinding(
            surface=_SURFACE, location=f"{mime}:structure", channel=Channel.HIDDEN.value,
            severity=severity, kind=kind, reason=f"media structure: {kind}",
            excerpt=excerpt, category=OwaspLLM.LLM03_SUPPLY_CHAIN,
            source=filename or mime,
        ))
        result.risk = max(result.risk, severity)
        result.reasons.append(kind)

    if result.risk >= th.block:
        result.verdict = Verdict.BLOCK
        result.quarantined = True
    elif result.risk >= th.quarantine and result.verdict == Verdict.ALLOW:
        result.verdict = Verdict.REVIEW
        result.quarantined = True

    result.meta.update({
        "filename": filename, "bytes": len(raw), "providers": providers(),
        "channels": {s.channel.value: 1 for s in segments},
    })
    # The honesty flag: a caller must be able to distinguish "inspected and
    # clean" from "nothing to inspect because we cannot read this channel".
    result.meta["fully_analysed"] = all(
        v.startswith("analysed") for v in coverage.values()) if coverage else False
    return result
