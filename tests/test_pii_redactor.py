"""Tests for PII detection, redaction, and reversible pseudonymization."""

from hypothesis import given
from hypothesis import strategies as st

from src.guardrails.models import PIIType
from src.guardrails.pii_redactor import PIIRedactor


def test_structured_pii_redaction() -> None:
    redactor = PIIRedactor()
    text = (
        "User contact: john.doe@enterprise.ie, Phone: +353 87 123 4567, "
        "PPSN: 1234567T, IBAN: IE29AIBK93115212345678, IP: 192.168.1.1"
    )

    result = redactor.redact_and_pseudonymize(text)
    assert len(result.entities) == 5

    types = [e.pii_type for e in result.entities]
    assert PIIType.EMAIL in types
    assert PIIType.PHONE in types
    assert PIIType.IRISH_PPSN in types
    assert PIIType.IBAN in types
    assert PIIType.IPV4 in types

    assert "john.doe@enterprise.ie" not in result.sanitized_text
    assert "<EMAIL_1>" in result.sanitized_text
    assert "<IRISH_PPSN_1>" in result.sanitized_text

    # Verify reversible restoration
    restored = redactor.restore(result.sanitized_text, result.token_map)
    assert restored == text


def test_repeated_entity_consistent_token() -> None:
    redactor = PIIRedactor()
    text = "Send email to alice@tech.com or CC alice@tech.com please."
    result = redactor.redact_and_pseudonymize(text)

    # Both occurrences should map to <EMAIL_1>
    assert result.sanitized_text.count("<EMAIL_1>") == 2
    assert "<EMAIL_2>" not in result.sanitized_text
    assert redactor.restore(result.sanitized_text, result.token_map) == text


def test_luhn_credit_card_validation() -> None:
    redactor = PIIRedactor()
    # Invalid card number (fails Luhn)
    invalid_cc = "4532 0150 0000 0000"
    res1 = redactor.redact_and_pseudonymize(f"Card: {invalid_cc}")
    assert len(res1.entities) == 0

    # Valid card number (passes Luhn) - standard test Visa
    valid_cc = "4532 0150 0000 0007"
    res2 = redactor.redact_and_pseudonymize(f"Card: {valid_cc}")
    assert len(res2.entities) == 1
    assert res2.entities[0].pii_type == PIIType.CREDIT_CARD


@given(st.emails())
def test_hypothesis_email_reversible(email: str) -> None:
    redactor = PIIRedactor()
    text = f"Contact me at {email}."
    result = redactor.redact_and_pseudonymize(text)

    if result.entities:
        restored = redactor.restore(result.sanitized_text, result.token_map)
        assert restored == text
