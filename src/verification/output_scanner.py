"""
LLM Output Scanner (second security boundary)
=============================================

Even with a clean input, an LLM can echo or hallucinate PII. Every response
from the approved model is re-scanned with the independent verifier before it
is shown to the user; any finding is redacted and the response is flagged.

    scanner = LLMOutputScanner()
    result = scanner.scan(response_text)
    result.allowed            # False if anything PII-like was found
    result.redacted_response  # safe to display either way

**Ownership:** Person 4 (Security Policy, Independent Verification & Audit)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from src.sanitization.text_redactor import TextRedactor
from src.verification.verifier import IndependentVerifier, VerificationReport


@dataclass
class OutputScanResult:
    allowed: bool
    redacted_response: str
    verification_report: VerificationReport

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "status": self.verification_report.status_code,
            "findings": [f.to_dict() for f in self.verification_report.findings],
        }


class LLMOutputScanner:
    def __init__(
        self,
        verifier: Optional[IndependentVerifier] = None,
        redactor: Optional[TextRedactor] = None,
    ):
        self.verifier = verifier or IndependentVerifier.from_policy()
        self.redactor = redactor or TextRedactor()

    def scan(self, response_text: str) -> OutputScanResult:
        text = response_text or ""
        if not text.strip():
            # An empty answer leaks nothing.
            return OutputScanResult(True, text, VerificationReport(units_scanned=1))

        report = self.verifier.verify_text(text, unit_id="llm_output", source="llm_output")
        redacted = self.redactor.redact_text(text, report.findings)
        if redacted.unapplied_entity_ids:
            # Cannot show a partially redacted answer.
            return OutputScanResult(False, "[RESPONSE WITHHELD: PII DETECTED]", report)
        return OutputScanResult(report.passed, redacted.text, report)
