"""Runtime configuration.

Secrets and tunables come from the environment (R8: secrets from env, secure by
default). All values have safe, offline-friendly defaults so the detection
engine and benchmark run with zero configuration, while the Docker deployment
overrides them via ``.env``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Thresholds:
    """Decision thresholds. Kept conservative to control false positives (G3)."""

    block: float = 0.75            # >= block outright
    review_low: float = 0.45       # [review_low, block) -> uncertainty band -> judge
    # A benign prompt tripping only isolated trigger words is calibrated down.
    over_defense_relief: float = 0.20
    # High normalization risk that classifiers ignore is itself an evasion signal.
    normalization_tripwire: float = 0.55
    # Two classifiers disagreeing by more than this is a threat signal.
    disagreement_tripwire: float = 0.40


@dataclass(frozen=True)
class SurfaceFlags:
    """Independent on/off switch per surface module (v2.1).

    Every surface is additive: switching one off restores exactly the v2.0
    behaviour for that route, so a deployment can adopt them one at a time.
    Set e.g. ``AEGIS_SURFACE_RAG=0`` to disable the RAG layer.
    """

    browser: bool = _env_bool("AEGIS_SURFACE_BROWSER", True)
    documents: bool = _env_bool("AEGIS_SURFACE_DOCUMENTS", True)
    rag: bool = _env_bool("AEGIS_SURFACE_RAG", True)
    memory: bool = _env_bool("AEGIS_SURFACE_MEMORY", True)
    tools: bool = _env_bool("AEGIS_SURFACE_TOOLS", True)
    agent: bool = _env_bool("AEGIS_SURFACE_AGENT", True)
    multimodal: bool = _env_bool("AEGIS_SURFACE_MULTIMODAL", True)

    def enabled(self, name: str) -> bool:
        return bool(getattr(self, name, False))


@dataclass(frozen=True)
class SurfaceThresholds:
    """Decision thresholds for surface (non-prompt) content.

    Deliberately *stricter* than the prompt thresholds. A user's own prompt is
    allowed to be weird — that is what over-defense relief protects. Retrieved
    documents, tool arguments, and stored memories have no such licence: an
    imperative aimed at the model inside a data channel is anomalous by
    construction, so the block bar sits lower.
    """

    block: float = _env_float("AEGIS_SURFACE_BLOCK", 0.60)
    quarantine: float = _env_float("AEGIS_SURFACE_QUARANTINE", 0.40)
    # Per-segment instruction density above which a document is treated as a
    # carrier rather than a document that merely quotes an instruction once.
    density: float = _env_float("AEGIS_SURFACE_DENSITY", 0.25)
    # S14-equivalent caps for surface content (bytes / items).
    max_segment_chars: int = _env_int("AEGIS_SURFACE_MAX_SEGMENT_CHARS", 8_000)
    max_segments: int = _env_int("AEGIS_SURFACE_MAX_SEGMENTS", 400)
    max_artifact_bytes: int = _env_int("AEGIS_SURFACE_MAX_ARTIFACT_BYTES", 8_000_000)


@dataclass(frozen=True)
class Settings:
    # --- offline / secure-by-default posture ---
    offline: bool = _env_bool("AEGIS_OFFLINE", True)
    # Fail-closed by default; per-tenant policy can relax to fail-open with alarm.
    default_fail_mode: str = os.getenv("AEGIS_DEFAULT_FAIL_MODE", "closed")

    # --- limits (S5 / S14) ---
    max_prompt_chars: int = _env_int("AEGIS_MAX_PROMPT_CHARS", 32_000)
    layer_timeout_ms: int = _env_int("AEGIS_LAYER_TIMEOUT_MS", 750)
    judge_budget_per_min: int = _env_int("AEGIS_JUDGE_BUDGET_PER_MIN", 30)
    rate_limit_per_min: int = _env_int("AEGIS_RATE_LIMIT_PER_MIN", 120)
    context_window_turns: int = _env_int("AEGIS_CONTEXT_TURNS", 6)
    # Whole-conversation inspection (v2.1 audit fix): how many of the most
    # recent messages to inspect per request. Older turns were inspected on the
    # request that introduced them, and an unbounded array is a DoS vector.
    conversation_max_messages: int = _env_int("AEGIS_CONVERSATION_MAX_MESSAGES", 40)
    inspect_conversation: bool = _env_bool("AEGIS_INSPECT_CONVERSATION", True)

    # --- timing side-channel defense (S9) ---
    response_floor_ms: int = _env_int("AEGIS_RESPONSE_FLOOR_MS", 0)
    response_jitter_ms: int = _env_int("AEGIS_RESPONSE_JITTER_MS", 0)

    # --- infra (optional; in-memory fallbacks when unset) ---
    database_url: str = os.getenv("AEGIS_DATABASE_URL", "")
    redis_url: str = os.getenv("AEGIS_REDIS_URL", "")
    upstream_url: str = os.getenv("AEGIS_UPSTREAM_URL", "")  # empty -> mock backend
    upstream_api_key: str = os.getenv("AEGIS_UPSTREAM_API_KEY", "")

    # --- admin / transport (S10) ---
    admin_api_key: str = os.getenv("AEGIS_ADMIN_API_KEY", "")
    cors_origins: str = os.getenv("AEGIS_CORS_ORIGINS", "http://localhost:5173")
    # Server-side pepper for API-key HMAC. API keys are high-entropy random
    # tokens, so a fast keyed hash (not a slow password KDF) is the correct,
    # non-DoS choice for per-request verification.
    key_pepper: str = os.getenv("AEGIS_KEY_PEPPER", "")

    # --- audit at rest (S7) ---
    audit_encryption_key: str = os.getenv("AEGIS_AUDIT_KEY", "")
    redact_pii_in_logs: bool = _env_bool("AEGIS_REDACT_PII", True)
    log_retention_days: int = _env_int("AEGIS_LOG_RETENTION_DAYS", 30)

    # --- optional ML models (pluggable; heuristic fallback otherwise) ---
    hf_model_dir: str = os.getenv("AEGIS_HF_MODEL_DIR", "")

    thresholds: Thresholds = field(default_factory=Thresholds)
    surfaces: SurfaceFlags = field(default_factory=SurfaceFlags)
    surface_thresholds: SurfaceThresholds = field(default_factory=SurfaceThresholds)


settings = Settings()
