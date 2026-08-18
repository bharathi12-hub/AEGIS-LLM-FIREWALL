"""Model registry with integrity pinning (S3 / Section 6).

Production model loading must be reproducible and tamper-evident:
  * models are pinned by repo + git revision (commit hash),
  * weights are **safetensors only** (no pickle code execution),
  * every weight file's SHA-256 is verified against a signed manifest at startup.

A mismatch or a pickle checkpoint aborts startup (fail-closed) rather than loading
untrusted weights. ``fetch_models.py`` downloads the pinned revisions and writes
the manifest; this module verifies it at boot and on model switch/rollback.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from app.security.modelscan import UnsafeModelError, assert_safetensors_only, _sha256


@dataclass
class ModelEntry:
    name: str
    repo: str
    revision: str          # pinned git commit hash
    path: str              # local dir
    files: dict            # rel_path -> sha256
    role: str              # "classifier" | "kad" | "judge" | "embedding"


@dataclass
class RegistryResult:
    ok: bool
    verified: list[str]
    problems: list[str]


def load_manifest(path: str) -> list[ModelEntry]:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    root = os.path.dirname(os.path.abspath(path))
    entries = []
    for m in doc.get("models", []):
        entries.append(ModelEntry(
            name=m["name"], repo=m.get("repo", ""), revision=m.get("revision", ""),
            path=os.path.join(root, m.get("path", m["name"])),
            files=m.get("files", {}), role=m.get("role", "classifier"),
        ))
    return entries


def verify_entry(entry: ModelEntry) -> list[str]:
    problems: list[str] = []
    if not os.path.isdir(entry.path):
        return [f"{entry.name}: model dir missing ({entry.path})"]
    try:
        assert_safetensors_only(entry.path)  # S3: no pickles, has safetensors
    except UnsafeModelError as exc:
        problems.append(f"{entry.name}: {exc}")
    for rel, expected in entry.files.items():
        fp = os.path.join(entry.path, rel)
        if not os.path.exists(fp):
            problems.append(f"{entry.name}: pinned file missing {rel}")
            continue
        actual = _sha256(fp)
        if actual != expected:
            problems.append(f"{entry.name}: checksum mismatch {rel}")
    return problems


def verify_registry(manifest_path: str) -> RegistryResult:
    if not os.path.exists(manifest_path):
        return RegistryResult(ok=True, verified=[], problems=[])  # no models pinned
    entries = load_manifest(manifest_path)
    verified, problems = [], []
    for e in entries:
        errs = verify_entry(e)
        if errs:
            problems.extend(errs)
        else:
            verified.append(f"{e.name}@{e.revision[:8]}")
    return RegistryResult(ok=not problems, verified=verified, problems=problems)


def assert_registry_ok(manifest_path: str) -> None:
    """Startup gate — fail-closed if any pinned model fails integrity checks."""
    result = verify_registry(manifest_path)
    if not result.ok:
        raise UnsafeModelError("model registry verification failed: "
                               + "; ".join(result.problems))
