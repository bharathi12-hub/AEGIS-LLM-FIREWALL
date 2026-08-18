"""Upstream LLM client.

Forwards the FIREWALL-SANITIZED text (R9 parity — never the raw bytes) to a real
OpenAI-compatible endpoint when ``AEGIS_UPSTREAM_URL`` is set, otherwise to the
offline mock backend. The system prompt is canary-decorated by the caller.
"""
from __future__ import annotations

from app.config import settings
from app.upstream import mock_backend


async def complete(
    *, model: str, sanitized_user_text: str, system_prompt: str = "",
    canary_token: str = "",
) -> dict:
    if settings.upstream_url:
        return await _forward_real(model, sanitized_user_text, system_prompt)
    content = mock_backend.complete(sanitized_user_text, system_prompt, canary_token)
    return mock_backend.as_openai_response(model, content)


async def _forward_real(model: str, sanitized_user_text: str,
                        system_prompt: str) -> dict:  # pragma: no cover
    import httpx  # type: ignore
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": sanitized_user_text})
    headers = {"Content-Type": "application/json"}
    if settings.upstream_api_key:
        headers["Authorization"] = f"Bearer {settings.upstream_api_key}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            settings.upstream_url.rstrip("/") + "/v1/chat/completions",
            json={"model": model, "messages": messages}, headers=headers,
        )
        resp.raise_for_status()
        return resp.json()
