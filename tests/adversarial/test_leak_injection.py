"""
Adversarial Testing: Deliberate PII Leak Injections & Fail-Closed Gate Verification
Person 5: Evaluation Benchmark, Adversarial Testing & UI Lead
Roadmap: Day 13 / 17 Deliberate Leak Injection & Fail-Closed Assurance

Simulates deliberate misses and evasions in the primary detector to verify
that the Independent Verifier and Fail-Closed Security Gate guarantee a
ZERO DOCUMENT LEAK RATE.
"""

import pytest
from src.verification.verifier import IndependentVerifier
from src.verification.gate import AIReadinessGate, BLOCK, PASS
from src.policy.policy import PolicyEngine
from src.schema.entities import EntityType


class TestAdversarialLeakInjection:
    """Deliberate leak injection suite verifying fail-closed zero-tolerance boundary."""

    def test_unredacted_pii_intercepted_by_verifier(self):
        """Simulate a detector blind spot: unredacted SSN reaches verifier."""
        leaked_text = "Internal note: Employee SSN is 492-01-9238 for tax record."

        verifier = IndependentVerifier()
        report = verifier.verify_text(leaked_text)

        assert not report.passed
        assert report.residual_risk in ["CRITICAL", "HIGH"]
        assert any(f.entity_type == "SSN" for f in report.findings)

    def test_leak_injection_fails_closed_at_gate(self):
        """When verifier identifies residual PII, Gate must issue fail-closed BLOCK."""
        leaked_text = "Executive wire transfer card: 4111222233334444 approved."

        verifier = IndependentVerifier()
        report = verifier.verify_text(leaked_text)

        policy = PolicyEngine()
        policy_res = policy.apply([])

        gate = AIReadinessGate()
        decision = gate.evaluate(
            document_id="doc_leaked_card",
            verifier_report=report,
            policy_result=policy_res,
            ocr_confidences={1: 0.99},
        )

        assert decision.decision == BLOCK
        assert decision.ai_ready is False
        assert any(r.code == "RESIDUAL_LEAK_DETECTED" for r in decision.reasons)

    def test_partial_redaction_leak_blocked(self):
        """A broken or partial redaction (e.g. cue intact + unredacted value) is blocked."""
        partially_redacted_text = "SSN: 293-11-4829 [REDACTED_PERSON]"

        verifier = IndependentVerifier()
        report = verifier.verify_text(partially_redacted_text)

        assert not report.passed
        assert any(f.entity_type == "SSN" for f in report.findings)

        gate = AIReadinessGate()
        decision = gate.evaluate(
            document_id="doc_partial_redaction",
            verifier_report=report,
            policy_result=PolicyEngine().apply([]),
            ocr_confidences={1: 0.99},
        )
        assert decision.decision == BLOCK

    def test_policy_action_unredacted_fails_closed(self):
        """If an entity is marked REDACT but text remains untouched, Gate blocks."""
        # Mock an entity that was marked REDACT but remained in unredacted entities
        class MockEntity:
            def __init__(self):
                self.entity_type = "SSN"
                self.risk = "CRITICAL"
                self.action = "UNRESOLVED"  # Failed to resolve/apply
                self.page = 1
                self.value_hash = "abc12345"

        verifier = IndependentVerifier()
        clean_report = verifier.verify_text("Clean text")

        policy_res = PolicyEngine().apply([])
        gate = AIReadinessGate()

        decision = gate.evaluate(
            document_id="doc_unresolved_entity",
            verifier_report=clean_report,
            policy_result=policy_res,
            entities=[MockEntity()],
            ocr_confidences={1: 0.99},
        )

        assert decision.decision == BLOCK
        assert any(r.code in ["CRITICAL_PII_PRESENT", "UNRESOLVED_ACTION", "UNREDACTED_ENTITIES"] for r in decision.reasons)

    def test_zero_tolerance_leak_rate_contract(self):
        """
        Evaluates a suite of 10 diverse PII leak injections (PAN, Passport, Phone, Email, SSN, Card).
        Asserts that exactly 0 leaks bypass the Gate (100% block rate on unredacted PII).
        """
        leak_payloads = [
            "SSN: 123-45-6789",
            "Tax PAN: ABCDE1234F",
            "Passport Number: Z9182736",
            "Corporate Card: 4000123456789010",
            "Contact phone: +1-555-432-1098",
            "Email: executive-leak@corp-internal.net",
            "Aadhaar UID: 2345 6789 0123",
            "Bank IFSC: SBIN0001234 with account 918273645",
            "S S N : 9 8 7 - 6 5 - 4 3 2 1",
            "Direct mobile: (415) 555-9012",
        ]

        verifier = IndependentVerifier()
        gate = AIReadinessGate()
        policy = PolicyEngine()
        policy_res = policy.apply([])

        blocked_count = 0
        for idx, payload in enumerate(leak_payloads):
            report = verifier.verify_text(payload)
            decision = gate.evaluate(
                document_id=f"leak_test_{idx}",
                verifier_report=report,
                policy_result=policy_res,
                ocr_confidences={1: 0.99},
            )
            if decision.decision == BLOCK:
                blocked_count += 1

        # Zero Document Leak Rate: 10/10 must be blocked!
        assert blocked_count == len(leak_payloads), f"Leak bypass detected! {blocked_count}/{len(leak_payloads)} blocked."
