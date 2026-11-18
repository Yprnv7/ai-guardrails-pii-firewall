"""Adversarial jailbreak detection and Unicode homoglyph normalization."""

from __future__ import annotations

import re
import time
import unicodedata
from typing import ClassVar

from src.guardrails.models import JailbreakAudit, JailbreakRisk


class JailbreakDetector:
    """Normalizes Unicode obfuscations and blocks adversarial prompt extraction and jailbreaks."""

    # Cyrillic and Greek lookalikes to ASCII Latin
    HOMOGLYPH_MAP: ClassVar[dict[str, str]] = {
        "а": "a", "А": "A",
        "с": "c", "С": "C",
        "е": "e", "Е": "E",
        "і": "i", "І": "I",
        "ј": "j", "Ј": "J",
        "о": "o", "О": "O",
        "р": "p", "Р": "P",
        "ѕ": "s", "Ѕ": "S",
        "х": "x", "Х": "X",
        "у": "y", "У": "Y",
        "В": "B", "Н": "H", "М": "M", "Т": "T",
    }

    ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u00A0]")

    JAILBREAK_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"\bdo\s+anything\s+now\b", re.IGNORECASE),
        re.compile(r"\bDAN\s+(mode|\d+\.\d+)?\b", re.IGNORECASE),
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(the\s+)?(system\s+prompt|guidelines|safety)", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+an\s+unrestricted\s+ai", re.IGNORECASE),
        re.compile(r"reveal\s+(the\s+)?(system\s+prompt|initial\s+instructions|developer\s+message)", re.IGNORECASE),
        re.compile(r"output\s+everything\s+above\s+this\s+line", re.IGNORECASE),
        re.compile(r"bypass\s+(safety|content)\s+filters?", re.IGNORECASE),
        re.compile(r"roleplay\s+as\s+(an?\s+)?(unfiltered\s+)?(evil|unrestricted|adversarial)", re.IGNORECASE),
        re.compile(r"developer\s+mode\s+enabled", re.IGNORECASE),
    ]

    def normalize_text(self, text: str) -> str:
        """Applies NFKC normalization, strips zero-width chars, and maps homoglyphs."""
        # Step 1: NFKC normalization
        normalized = unicodedata.normalize("NFKC", text)

        # Step 2: Strip zero-width and invisible characters
        normalized = self.ZERO_WIDTH_CHARS.sub("", normalized)

        # Step 3: Replace known homoglyphs
        chars = [self.HOMOGLYPH_MAP.get(c, c) for c in normalized]
        return "".join(chars)

    def audit(self, text: str) -> JailbreakAudit:
        start_time = time.perf_counter()

        normalized = self.normalize_text(text)
        triggered: list[str] = []

        for pattern in self.JAILBREAK_PATTERNS:
            if pattern.search(normalized):
                triggered.append(pattern.pattern)

        # Check for base64 encoded injection suspicion (long base64 strings)
        if re.search(r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b", text):
            triggered.append("suspicious_base64_payload")

        risk_level = JailbreakRisk.SAFE
        if len(triggered) >= 1:
            risk_level = JailbreakRisk.ATTACK_DETECTED
        elif "system prompt" in normalized.lower() or "override" in normalized.lower():
            risk_level = JailbreakRisk.SUSPICIOUS

        elapsed_us = (time.perf_counter() - start_time) * 1_000_000.0

        return JailbreakAudit(
            is_safe=risk_level == JailbreakRisk.SAFE,
            risk_level=risk_level,
            triggered_patterns=triggered,
            normalized_text=normalized,
            latency_us=round(elapsed_us, 2),
        )
