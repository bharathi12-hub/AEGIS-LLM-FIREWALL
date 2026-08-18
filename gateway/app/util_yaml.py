"""Tiny YAML-subset loader.

AEGIS keeps its rules and policies in YAML (policy-as-code, Section 6). PyYAML is
installed in the Docker image, but the pure-stdlib profile (tests, benchmark,
offline dev) must load these files with zero dependencies. This parser supports
the regular subset we actually author: nested mappings, block lists of scalars
or mappings, quoted/unquoted scalars, ints/floats/bools/null, and ``#`` comments.

It assumes consistent 2-space indentation (as our files use). When PyYAML is
available, ``load_yaml`` delegates to it.
"""
from __future__ import annotations

import re
from typing import Any

try:  # pragma: no cover - exercised only when PyYAML is installed
    import yaml as _pyyaml
except Exception:  # noqa: BLE001
    _pyyaml = None


def _coerce_scalar(tok: str) -> Any:
    tok = tok.strip()
    if tok in ("", "~") or tok.lower() == "null":
        return None
    # Minimal flow-style collections: [], {}, [a, b, c].
    if tok == "[]":
        return []
    if tok == "{}":
        return {}
    if len(tok) >= 2 and tok[0] == "[" and tok[-1] == "]":
        inner = tok[1:-1].strip()
        return [_coerce_scalar(p) for p in inner.split(",")] if inner else []
    if len(tok) >= 2 and tok[0] in "\"'" and tok[-1] == tok[0]:
        inner = tok[1:-1]
        if tok[0] == "'":
            # YAML single-quote escaping: '' -> ' (no backslash processing).
            return inner.replace("''", "'")
        return inner
    low = tok.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"-?\d+", tok):
        return int(tok)
    if re.fullmatch(r"-?\d*\.\d+", tok):
        return float(tok)
    return tok


class _Line:
    __slots__ = ("indent", "content")

    def __init__(self, indent: int, content: str):
        self.indent = indent
        self.content = content


def _strip_comment(line: str) -> str:
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def _preprocess(text: str) -> list[_Line]:
    lines: list[_Line] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        content = _strip_comment(raw)
        if not content.strip():
            continue
        stripped = content.lstrip(" ")
        lines.append(_Line(len(content) - len(stripped), stripped))
    return lines


def _is_map_entry(body: str) -> bool:
    return re.match(r"^[^:'\"]+:(\s|$)", body) is not None


def _parse_node(lines: list[_Line], i: int, indent: int) -> tuple[Any, int]:
    if i >= len(lines):
        return None, i
    if lines[i].content.startswith("- "):
        return _parse_list(lines, i, indent)
    return _parse_map(lines, i, indent)


def _parse_list(lines: list[_Line], i: int, indent: int) -> tuple[list, int]:
    items: list[Any] = []
    while i < len(lines) and lines[i].indent == indent and lines[i].content.startswith("- "):
        body = lines[i].content[2:]
        if body.strip() == "":
            i += 1
            if i < len(lines) and lines[i].indent > indent:
                val, i = _parse_node(lines, i, lines[i].indent)
                items.append(val)
            else:
                items.append(None)
        elif _is_map_entry(body):
            # Rewrite "- key: val" as a mapping line at indent+2 and parse it.
            lines[i] = _Line(indent + 2, body)
            val, i = _parse_map(lines, i, indent + 2)
            items.append(val)
        else:
            items.append(_coerce_scalar(body))
            i += 1
    return items, i


def _parse_map(lines: list[_Line], i: int, indent: int) -> tuple[dict, int]:
    result: dict[str, Any] = {}
    while i < len(lines) and lines[i].indent == indent and not lines[i].content.startswith("- "):
        key, _, rest = lines[i].content.partition(":")
        key = key.strip()
        rest = rest.strip()
        i += 1
        if rest == "":
            if i < len(lines) and lines[i].indent > indent:
                val, i = _parse_node(lines, i, lines[i].indent)
                result[key] = val
            else:
                result[key] = None
        else:
            result[key] = _coerce_scalar(rest)
    return result, i


def loads(text: str) -> Any:
    if _pyyaml is not None:
        return _pyyaml.safe_load(text)
    lines = _preprocess(text)
    if not lines:
        return None
    value, _ = _parse_node(lines, 0, lines[0].indent)
    return value


def load_yaml(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return loads(fh.read())
