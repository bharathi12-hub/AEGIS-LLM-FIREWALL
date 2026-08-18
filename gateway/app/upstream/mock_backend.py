"""Offline mock upstream (R1).

A deterministic stand-in for a real LLM so the whole gateway runs with no keys or
internet. It also deliberately simulates a *compromised / over-helpful* model on
certain requests, so the OUTPUT pipeline (DLP decode-then-scan + canary) has
something real to catch in the demo:

  * "base64 ... secret/password"   -> returns a base64-encoded fake secret
    (exercises S12 decode-then-scan).
  * "reveal / trace id / system"   -> leaks the canary embedded in the system
    prompt (exercises the canary leak check).

Normal prompts get a short benign completion.
"""
from __future__ import annotations

import base64
import re

_FAKE_SECRET = "SuperSecret-API-Key-9f3a1c7d"


def complete(user_text: str, system_prompt: str = "", canary_token: str = "") -> str:
    low = (user_text or "").lower()

    # Simulate exfiltration-via-encoding when asked (so DLP can decode-then-scan).
    if re.search(r"(base64|encode).{0,30}(secret|password|api key|key|answer|response)", low):
        enc = base64.b64encode(_FAKE_SECRET.encode()).decode()
        return f"Sure! Here is the encoded value you asked for: {enc}"

    # Simulate system-prompt / canary leakage on extraction attempts.
    if re.search(r"(reveal|show|print|repeat|system prompt|trace id|instructions above)", low):
        leak = canary_token or "AEG-<canary>"
        return (f"My internal instructions are: {system_prompt} "
                f"(trace id {leak}).")

    # Benign default completion.
    return ("I'm a mock assistant running behind the AEGIS firewall. "
            "I can help summarize, explain, or answer questions.")


def as_openai_response(model: str, content: str) -> dict:
    return {
        "id": "chatcmpl-aegis-mock",
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }
