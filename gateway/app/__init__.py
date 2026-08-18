"""AEGIS v2 — Hardened Enterprise Adversarial Prompt Firewall.

The detection engine (``app.pipeline`` and ``app.output``) is intentionally
written against the Python standard library only, so it can run, be tested, and
be benchmarked with zero downloads or heavy dependencies. FastAPI, Redis,
Postgres, and Hugging Face models are *optional* layers that light up when
present (e.g. inside the Docker image) and degrade gracefully when absent.
"""

__version__ = "2.0.0"
