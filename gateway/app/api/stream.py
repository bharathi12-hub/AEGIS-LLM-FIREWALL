"""Streaming variant of the proxy (SSE).

AEGIS inspects the FULL input and the FULL upstream answer BEFORE streaming, then
streams the already-cleared answer in chunks. Inspecting before emitting is a
deliberate security choice: we never stream un-inspected model tokens to the
client (which would defeat output DLP / canary).
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import StreamingResponse

from app.api.proxy import _principal, run_input_inspection
from app.api.schemas import ChatCompletionRequest
from app.output import canary as canary_mod
from app.output.dlp import scan_output
from app.policy.engine import get_engine
from app.upstream import llm_client

router = APIRouter()


@router.post("/v1/chat/completions/stream")
async def chat_completions_stream(
    body: ChatCompletionRequest,
    authorization: str | None = Header(default=None),
    x_aegis_session: str | None = Header(default=None),
):
    principal = _principal(authorization)
    model = body.model
    user_text = body.latest_user_text()
    if not user_text:
        raise HTTPException(status_code=400, detail="no user message")
    session_id = x_aegis_session or f"{principal.tenant_id}:{principal.key_id}"
    policy = get_engine().effective(principal.tenant_id)

    outcome = run_input_inspection(user_text, principal, policy, session_id)

    async def gen():
        if outcome.blocked:
            yield _sse({"aegis": {"verdict": "block", "category": outcome.category}})
            yield _sse({"choices": [{"delta": {"content": "[AEGIS] blocked."},
                                     "finish_reason": "content_filter"}]})
            yield "data: [DONE]\n\n"
            return
        canary = canary_mod.get_manager().issue(session_id)
        decorated = canary_mod.get_manager().decorate_system_prompt(
            session_id, "You are a helpful assistant.")
        upstream = await llm_client.complete(
            model=model, sanitized_user_text=outcome.forward_text,
            system_prompt=decorated, canary_token=canary.token)
        answer = upstream["choices"][0]["message"]["content"]
        dlp = scan_output(answer, canary_tokens=canary_mod.get_manager().tokens_for(session_id))
        if dlp.blocked:
            answer = "[AEGIS] response withheld (DLP/canary)."
        # Stream the already-cleared answer word by word.
        for word in answer.split(" "):
            yield _sse({"choices": [{"delta": {"content": word + " "}}]})
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


def _sse(obj: dict) -> str:
    return "data: " + json.dumps(obj) + "\n\n"
