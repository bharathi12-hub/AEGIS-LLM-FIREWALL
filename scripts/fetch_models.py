"""Fetch + pin + verify the real detector models (S3).

Downloads each model in models/manifest.json at its PINNED revision (commit hash),
enforces safetensors-only, computes SHA-256 for every weight file, and writes the
checksums back into the manifest. Re-running verifies integrity without
re-downloading.

    python scripts/fetch_models.py            # fetch/verify per models/manifest.json
    python scripts/fetch_models.py --verify   # verify only (offline, CI)

Requires network + `huggingface_hub` to download; verification is offline.
Llama-Prompt-Guard is license-gated: accept the license and set HF_TOKEN first.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "gateway"))

from app.security.modelscan import _sha256, assert_safetensors_only  # noqa: E402

MODELS_DIR = os.path.join(_ROOT, "models")
MANIFEST = os.path.join(MODELS_DIR, "manifest.json")


def _download(repo: str, revision: str, dest: str) -> None:
    from huggingface_hub import snapshot_download  # type: ignore
    snapshot_download(
        repo_id=repo, revision=revision, local_dir=dest,
        allow_patterns=["*.safetensors", "*.json", "tokenizer*", "*.model"],
        token=os.getenv("HF_TOKEN"),
    )


def run(verify_only: bool) -> int:
    if not os.path.exists(MANIFEST):
        print(f"No manifest at {MANIFEST}. Copy models/manifest.example.json first.")
        return 1
    with open(MANIFEST, encoding="utf-8") as fh:
        doc = json.load(fh)

    problems = 0
    for m in doc.get("models", []):
        dest = os.path.join(MODELS_DIR, m.get("path", m["name"]))
        if not verify_only:
            if m["revision"].strip("0") == "":
                print(f"! {m['name']}: set a real revision (commit hash) first")
                problems += 1
                continue
            print(f"Downloading {m['repo']}@{m['revision'][:8]} -> {dest}")
            _download(m["repo"], m["revision"], dest)

        try:
            assert_safetensors_only(dest)
        except Exception as exc:  # noqa: BLE001
            print(f"UNSAFE {m['name']}: {exc}")
            problems += 1
            continue

        computed = {}
        for rel in m.get("files", {}):
            fp = os.path.join(dest, rel)
            if not os.path.exists(fp):
                print(f"! {m['name']}: missing {rel}")
                problems += 1
                continue
            computed[rel] = _sha256(fp)

        if verify_only:
            for rel, expected in m.get("files", {}).items():
                if computed.get(rel) != expected:
                    print(f"MISMATCH {m['name']}:{rel}")
                    problems += 1
            print(f"verified {m['name']}")
        else:
            m["files"] = computed
            print(f"pinned checksums for {m['name']}: {list(computed)}")

    if not verify_only:
        with open(MANIFEST, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        print(f"Updated {MANIFEST}")
    return 1 if problems else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true", help="verify only, no download")
    args = ap.parse_args()
    raise SystemExit(run(args.verify))
