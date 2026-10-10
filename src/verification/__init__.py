"""
Verification Package (Person 4)
===============================

- verifier.py:       independent secondary PII scanner (does not use src.detection)
- residual_scan.py:  re-OCR residual check for pixel-burned images / PDF pages
- gate.py:           fail-closed AI readiness gate (PASS / BLOCK)
- checkpoint.py:     policy -> redaction -> verification -> gate -> audit
- output_scanner.py: scans LLM responses (second security boundary)

Heavier modules (checkpoint, output_scanner) are imported from their own
modules so that `import src.verification` stays lightweight.
"""

from src.verification.verifier import (
    IndependentVerifier,
    ResidualFinding,
    VerificationReport,
    VerificationUnit,
    verify_document,
)
from src.verification.residual_scan import ResidualScanner
from src.verification.gate import AIReadinessGate, GateDecision, GateReason

__all__ = [
    "IndependentVerifier",
    "ResidualFinding",
    "VerificationReport",
    "VerificationUnit",
    "verify_document",
    "ResidualScanner",
    "AIReadinessGate",
    "GateDecision",
    "GateReason",
]
