"""Data models for PII redaction, jailbreak detection, and proxy completions."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PIIType(str, Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    IBAN = "IBAN"
    IRISH_PPSN = "IRISH_PPSN"
    CREDIT_CARD = "CREDIT_CARD"
    IPV4 = "IPV4"
    SSN = "SSN"


class PIIEntity(BaseModel):
    pii_type: PIIType
    start: int
    end: int
    original_text: str
    pseudonym_token: str
    confidence: float = 1.0


class RedactionResult(BaseModel):
    original_text: str
    sanitized_text: str
    entities: list[PIIEntity]
    token_map: dict[str, str]  # pseudonym_token -> original_text
    processing_time_us: float


class JailbreakRisk(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK_DETECTED = "ATTACK_DETECTED"


class JailbreakAudit(BaseModel):
    is_safe: bool
    risk_level: JailbreakRisk
    triggered_patterns: list[str] = Field(default_factory=list)
    normalized_text: str
    latency_us: float


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = "gpt-4o-mini"
    messages: list[ChatMessage]
    temperature: float = 0.7
    max_tokens: int = 500
    session_id: str = "default-tenant"


class ChatChoice(BaseModel):
    index: int
    message: ChatMessage
    finish_reason: str = "stop"


class GuardrailsMeta(BaseModel):
    pii_redacted_count: int
    jailbreak_blocked: bool
    rate_limited: bool
    total_guard_latency_ms: float
    audit_hash: str


class ChatCompletionResponse(BaseModel):
    id: str
    model: str
    choices: list[ChatChoice]
    guardrails_meta: GuardrailsMeta
    usage: dict[str, Any] = Field(default_factory=dict)
