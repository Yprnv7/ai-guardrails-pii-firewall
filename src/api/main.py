"""FastAPI reverse proxy and LLM guardrails firewall."""

from __future__ import annotations

import time
import uuid

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.guardrails.jailbreak_detector import JailbreakDetector
from src.guardrails.models import (
    ChatChoice,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    GuardrailsMeta,
    JailbreakAudit,
    RedactionResult,
)
from src.guardrails.pii_redactor import PIIRedactor
from src.guardrails.rate_limiter import TenantRateLimiter

app = FastAPI(
    title="AI Guardrails & PII Firewall API",
    description="Ultra-low-latency LLM security proxy, GDPR PII pseudonymization, and jailbreak defense.",
    version="0.1.0",
)

PII_ENGINE = PIIRedactor()
JAILBREAK_ENGINE = JailbreakDetector()
RATE_LIMITER = TenantRateLimiter(default_capacity=100.0, default_refill_rate=20.0)


class InspectRequest(BaseModel):
    text: str


class InspectResponse(BaseModel):
    redaction: RedactionResult
    jailbreak: JailbreakAudit
    audit_hash: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy", "service": "ai-guardrails-pii-firewall"}


@app.post("/v1/guardrails/inspect", response_model=InspectResponse)
def inspect_text(payload: InspectRequest) -> InspectResponse:
    if not payload.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")

    jb_res = JAILBREAK_ENGINE.audit(payload.text)
    redact_res = PII_ENGINE.redact_and_pseudonymize(jb_res.normalized_text)
    audit_hash = PII_ENGINE.generate_audit_hash(payload.text, redact_res.token_map)

    return InspectResponse(
        redaction=redact_res,
        jailbreak=jb_res,
        audit_hash=audit_hash,
    )


@app.post("/v1/chat/completions", response_model=ChatCompletionResponse)
def chat_completions(payload: ChatCompletionRequest) -> ChatCompletionResponse:
    start_time = time.perf_counter()

    # Step 1: Rate limiting check
    if not RATE_LIMITER.check_rate_limit(payload.session_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please back off.")

    if not payload.messages:
        raise HTTPException(status_code=400, detail="Messages array cannot be empty")

    last_user_msg = payload.messages[-1].content

    # Step 2: Jailbreak and prompt extraction audit
    jb_audit = JAILBREAK_ENGINE.audit(last_user_msg)
    if not jb_audit.is_safe:
        raise HTTPException(
            status_code=400,
            detail=f"Security Violation: Adversarial prompt rejected ({'; '.join(jb_audit.triggered_patterns)})",
        )

    # Step 3: PII Redaction & Pseudonymization
    redact_res = PII_ENGINE.redact_and_pseudonymize(jb_audit.normalized_text)
    audit_hash = PII_ENGINE.generate_audit_hash(last_user_msg, redact_res.token_map)

    # Step 4: Downstream simulation using sanitized prompt
    raw_simulated_reply = (
        f"Processed query regarding user data safely. Acknowledged: {redact_res.sanitized_text[:100]}"
    )

    # Step 5: Restore pseudonymized tokens in final response
    final_reply = PII_ENGINE.restore(raw_simulated_reply, redact_res.token_map)

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return ChatCompletionResponse(
        id=f"chatcmpl-{uuid.uuid4().hex[:12]}",
        model=payload.model,
        choices=[
            ChatChoice(
                index=0,
                message=ChatMessage(role="assistant", content=final_reply),
                finish_reason="stop",
            )
        ],
        guardrails_meta=GuardrailsMeta(
            pii_redacted_count=len(redact_res.entities),
            jailbreak_blocked=False,
            rate_limited=False,
            total_guard_latency_ms=round(elapsed_ms, 3),
            audit_hash=audit_hash,
        ),
        usage={"prompt_tokens": len(last_user_msg.split()), "completion_tokens": len(final_reply.split())},
    )
