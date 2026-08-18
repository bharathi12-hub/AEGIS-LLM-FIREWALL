"""Typed request/response models (input validation hardening).

Malformed requests are rejected with 422 by FastAPI/pydantic before any
detection work runs — no more trusting an untyped dict. Bodies are capped and
unknown fields tolerated (OpenAI clients send many extras).
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool", "developer"]
    # Content is a string or OpenAI content-parts; both handled downstream.
    content: str | list[dict[str, Any]] | None = None

    model_config = {"extra": "allow"}


class ChatCompletionRequest(BaseModel):
    model: str = "aegis-guarded-gpt"
    messages: list[ChatMessage] = Field(min_length=1, max_length=200)
    stream: bool = False

    model_config = {"extra": "allow"}

    def latest_user_text(self) -> str:
        for m in reversed(self.messages):
            if m.role == "user":
                c = m.content
                if isinstance(c, list):
                    return " ".join(p.get("text", "") for p in c if isinstance(p, dict))
                return c or ""
        return ""


class InspectRequest(BaseModel):
    text: str = Field(default="", max_length=200_000)


# ---------------------------------------------------------------------------
# Surface schemas (v2.1) — all additive; the models above are unchanged.
#
# Limits are generous but finite: an artifact big enough to exhaust the parser
# is rejected by pydantic before any detection work runs, which is the same
# S14 posture the prompt path already takes.
# ---------------------------------------------------------------------------

_MAX_ARTIFACT_CHARS = 10_000_000


class BrowserScanRequest(BaseModel):
    html: str = Field(default="", max_length=_MAX_ARTIFACT_CHARS)
    source: str = Field(default="", max_length=2048)


class DocumentScanRequest(BaseModel):
    content: str = Field(default="", max_length=_MAX_ARTIFACT_CHARS)
    encoding: Literal["text", "base64"] = "text"
    filename: str = Field(default="", max_length=512)
    media_type: str = Field(default="", max_length=128)
    source: str = Field(default="", max_length=2048)


class RagChunk(BaseModel):
    text: str = Field(default="", max_length=1_000_000)
    source: str = Field(default="", max_length=2048)
    trust: str = Field(default="unknown", max_length=32)
    score: float = 0.0
    chunk_id: str = Field(default="", max_length=128)
    metadata: dict[str, Any] | None = None


class RagScanRequest(BaseModel):
    chunks: list[RagChunk] = Field(default_factory=list, max_length=500)
    query: str = Field(default="", max_length=10_000)
    # source id -> trust tier, the deployment's statement of what it indexed
    registry: dict[str, str] | None = None


class MemoryRecordModel(BaseModel):
    text: str = Field(default="", max_length=100_000)
    origin: str = Field(default="unknown", max_length=32)
    record_id: str = Field(default="", max_length=128)


class MemoryScanRequest(BaseModel):
    mode: Literal["write", "recall"] = "write"
    records: list[MemoryRecordModel] = Field(default_factory=list, max_length=500)
    existing: list[MemoryRecordModel] = Field(default_factory=list, max_length=500)


class ToolPolicyModel(BaseModel):
    allowed_tools: list[str] = Field(default_factory=list, max_length=500)
    denied_tools: list[str] = Field(default_factory=list, max_length=500)
    allowed_roots: list[str] = Field(default_factory=list, max_length=100)
    allowed_hosts: list[str] = Field(default_factory=list, max_length=200)
    destructive_requires_approval: bool = True
    allow_private_network: bool = False
    role_tools: dict[str, list[str]] = Field(default_factory=dict)


class ToolCallRequest(BaseModel):
    name: str = Field(default="", max_length=256)
    arguments: dict[str, Any] = Field(default_factory=dict)
    description: str = Field(default="", max_length=100_000)
    server: str = Field(default="", max_length=256)
    caller_role: str = Field(default="default", max_length=64)
    user_intent: str = Field(default="", max_length=10_000)
    # Named tool_schema, not schema: `schema` shadows a pydantic BaseModel member.
    tool_schema: dict[str, Any] | None = None
    policy: ToolPolicyModel | None = None
    # Chain analysis: supplying a session id enables sequence detection across
    # calls, and result_text enables true taint tracking from source to sink.
    session_id: str = Field(default="", max_length=128)
    result_text: str = Field(default="", max_length=1_000_000)


class AgentMessageRequest(BaseModel):
    content: str = Field(default="", max_length=1_000_000)
    sender: str = Field(default="unknown", max_length=64)
    recipient: str = Field(default="unknown", max_length=64)
    taint: Literal["trusted", "derived", "untrusted"] = "untrusted"
    hop: int = Field(default=0, ge=0, le=1000)
    origin: str = Field(default="", max_length=512)


class MultimodalScanRequest(BaseModel):
    content: str = Field(default="", max_length=_MAX_ARTIFACT_CHARS)
    encoding: Literal["text", "base64"] = "base64"
    filename: str = Field(default="", max_length=512)
    media_type: str = Field(default="", max_length=128)
    # Callers that already run OCR/ASR can feed the recovered text in directly.
    ocr_text: str = Field(default="", max_length=1_000_000)
    transcript: str = Field(default="", max_length=1_000_000)
