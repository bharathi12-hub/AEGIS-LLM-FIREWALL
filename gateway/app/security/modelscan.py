"""Model supply-chain hygiene (S3).

Load ONLY safetensors; never torch.load pickles (arbitrary code execution). Pin
model revisions by commit hash; verify checksums at startup; refuse a model
directory that contains pickle checkpoints. This is the ModelScan-style gate the
CI runs and that the classifier/KAD/judge loaders call before touching a model.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os

# File extensions that indicate a pickle-backed checkpoint (code-execution risk).
_PICKLE_EXTS = {".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".h5", ".msgpack"}
_SAFE_EXTS = {".safetensors"}


class UnsafeModelError(RuntimeError):
    """Raised when a model directory violates safetensors-only policy."""


def scan_dir(model_dir: str) -> dict:
    """Return a report; raise UnsafeModelError if a pickle checkpoint is present."""
    weight_files = []
    unsafe = []
    for root, _dirs, files in os.walk(model_dir):
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            path = os.path.join(root, name)
            if ext in _PICKLE_EXTS:
                unsafe.append(os.path.relpath(path, model_dir))
            elif ext in _SAFE_EXTS:
                weight_files.append(os.path.relpath(path, model_dir))
    report = {
        "model_dir": model_dir,
        "safetensors": sorted(weight_files),
        "unsafe_pickles": sorted(unsafe),
        "ok": not unsafe and bool(weight_files),
    }
    return report


def assert_safetensors_only(model_dir: str) -> None:
    report = scan_dir(model_dir)
    if report["unsafe_pickles"]:
        raise UnsafeModelError(
            f"pickle checkpoints found in {model_dir}: {report['unsafe_pickles']}. "
            "AEGIS refuses to load non-safetensors weights (S3)."
        )
    if not report["safetensors"]:
        raise UnsafeModelError(f"no .safetensors weights found in {model_dir}")


def verify_checksums(model_dir: str, manifest_path: str | None = None) -> bool:
    """Verify sha256 of weight files against a pinned manifest (checksums.json).

    Manifest format: {"revision": "<git-sha>", "files": {"<rel>": "<sha256>"}}.
    Returns True if all present files match; raises on mismatch.
    """
    manifest_path = manifest_path or os.path.join(model_dir, "checksums.json")
    if not os.path.exists(manifest_path):
        return False
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    for rel, expected in manifest.get("files", {}).items():
        path = os.path.join(model_dir, rel)
        if not os.path.exists(path):
            raise UnsafeModelError(f"pinned file missing: {rel}")
        actual = _sha256(path)
        if actual != expected:
            raise UnsafeModelError(f"checksum mismatch for {rel}: {actual} != {expected}")
    return True


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ci_scan(root: str) -> int:
    """Entry point for CI: scan every model dir under root; nonzero exit on unsafe."""
    problems = 0
    for candidate in glob.glob(os.path.join(root, "**"), recursive=True):
        if os.path.isdir(candidate) and any(
            f.endswith(".safetensors") or os.path.splitext(f)[1].lower() in _PICKLE_EXTS
            for f in os.listdir(candidate) if os.path.isfile(os.path.join(candidate, f))
        ):
            report = scan_dir(candidate)
            if report["unsafe_pickles"]:
                print(f"UNSAFE  {candidate}: {report['unsafe_pickles']}")
                problems += 1
            else:
                print(f"ok      {candidate}: {len(report['safetensors'])} safetensors")
    return 1 if problems else 0


if __name__ == "__main__":
    import sys
    raise SystemExit(ci_scan(sys.argv[1] if len(sys.argv) > 1 else "."))
