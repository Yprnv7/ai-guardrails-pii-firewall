"""Deterministic high-speed PII redaction and reversible pseudonymization."""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from typing import ClassVar

from src.guardrails.models import PIIEntity, PIIType, RedactionResult


class PIIRedactor:
    """Detects structured PII entities, replaces them with reversible pseudonym tokens, and logs audit hashes."""

    SECRET_SALT = b"gdpr-audit-firewall-salt-2026"

    PATTERNS: ClassVar[dict[PIIType, re.Pattern[str]]] = {
        PIIType.EMAIL: re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.IGNORECASE
        ),
        PIIType.IRISH_PPSN: re.compile(
            r"\b\d{7}[A-Wa-w][A-Za-z]?\b"
        ),
        PIIType.IBAN: re.compile(
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,20}\b"
        ),
        PIIType.IPV4: re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
        PIIType.PHONE: re.compile(
            r"\b(?:\+\d{1,3}[-.\s]?)?\(?\d{2,3}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}\b"
        ),
        PIIType.CREDIT_CARD: re.compile(
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
        ),
    }

    @staticmethod
    def _luhn_check(number_str: str) -> bool:
        digits = [int(c) for c in number_str if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        reverse_digits = digits[::-1]
        for i, d in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = d * 2
                total += doubled - 9 if doubled > 9 else doubled
            else:
                total += d
        return total % 10 == 0

    def redact_and_pseudonymize(self, text: str) -> RedactionResult:
        start_time = time.perf_counter()

        entities: list[PIIEntity] = []
        token_map: dict[str, str] = {}  # pseudonym -> original
        value_to_token: dict[str, str] = {}  # original -> pseudonym
        counters: dict[PIIType, int] = {t: 0 for t in PIIType}

        # Find all matches across patterns
        matches: list[tuple[int, int, PIIType, str]] = []

        for pii_type, pattern in self.PATTERNS.items():
            for m in pattern.finditer(text):
                val = m.group(0)
                # For credit cards, verify Luhn
                if pii_type == PIIType.CREDIT_CARD and not self._luhn_check(val):
                    continue
                if pii_type == PIIType.PHONE:
                    digits_count = sum(1 for c in val if c.isdigit())
                    if digits_count > 12 or digits_count < 7:
                        continue
                matches.append((m.start(), m.end(), pii_type, val))

        # Sort matches by start position descending to replace from end to beginning cleanly
        # Filter overlapping matches (prefer longer match)
        matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        filtered_matches: list[tuple[int, int, PIIType, str]] = []
        last_end = -1
        for start, end, ptype, val in matches:
            if start >= last_end:
                filtered_matches.append((start, end, ptype, val))
                last_end = end

        # Construct sanitized string and entity list
        sanitized_chars = list(text)
        # Apply replacements from right to left to avoid index shifting
        for start, end, ptype, val in sorted(filtered_matches, key=lambda x: x[0], reverse=True):
            if val not in value_to_token:
                counters[ptype] += 1
                token = f"<{ptype.value}_{counters[ptype]}>"
                value_to_token[val] = token
                token_map[token] = val
            else:
                token = value_to_token[val]

            sanitized_chars[start:end] = list(token)
            entities.append(
                PIIEntity(
                    pii_type=ptype,
                    start=start,
                    end=end,
                    original_text=val,
                    pseudonym_token=token,
                )
            )

        sanitized_text = "".join(sanitized_chars)
        elapsed_us = (time.perf_counter() - start_time) * 1_000_000.0

        return RedactionResult(
            original_text=text,
            sanitized_text=sanitized_text,
            entities=list(reversed(entities)),
            token_map=token_map,
            processing_time_us=round(elapsed_us, 2),
        )

    @staticmethod
    def restore(sanitized_text: str, token_map: dict[str, str]) -> str:
        """Restores original PII values from pseudonymized tokens upon response receipt."""
        restored = sanitized_text
        for token, original in token_map.items():
            restored = restored.replace(token, original)
        return restored

    @classmethod
    def generate_audit_hash(cls, text: str, token_map: dict[str, str]) -> str:
        """Computes a GDPR Article 17 compliant HMAC-SHA256 audit digest."""
        payload = f"{text}|{json_canonical(token_map)}".encode()
        return hmac.new(cls.SECRET_SALT, payload, hashlib.sha256).hexdigest()


def json_canonical(data: dict[str, str]) -> str:
    items = sorted(data.items())
    return ";".join(f"{k}:{v}" for k, v in items)
