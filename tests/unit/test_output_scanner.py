"""
Unit Tests: LLM Output Scanner (Person 4, second security boundary)
"""

from src.verification.output_scanner import LLMOutputScanner


def test_clean_answer_allowed():
    result = LLMOutputScanner().scan("The policy requires quarterly access reviews (CTL-IAM-004).")
    assert result.allowed
    assert result.redacted_response.startswith("The policy requires")


def test_echoed_pii_redacted_and_flagged():
    result = LLMOutputScanner().scan("The employee's SSN is 219-45-7890 and email a.b@corp.com.")
    assert not result.allowed
    assert "219-45-7890" not in result.redacted_response
    assert "[REDACTED_SSN]" in result.redacted_response
    assert "[REDACTED_EMAIL]" in result.redacted_response
    assert "219-45-7890" not in str(result.to_dict())


def test_empty_answer():
    result = LLMOutputScanner().scan("")
    assert result.allowed and result.redacted_response == ""
