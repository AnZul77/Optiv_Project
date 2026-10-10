"""
Unit Tests: Fail-Closed AI Readiness Gate (Person 4)
====================================================

PASS requires every condition; each test removes exactly one of them and
expects BLOCK with the matching reason code.
"""

from types import SimpleNamespace

import pytest

from src.policy.policy import PolicyEngine
from src.schema.document import CanonicalDocument, EntityAnnotation
from src.schema.entities import Action, EntityType, PIIEntity
from src.security.input_safety import PromptSafetyReport
from src.security.integrity import IntegrityCheckResult
from src.verification.gate import AIReadinessGate, PASS_STATUS
from src.verification.verifier import IndependentVerifier, VerificationReport


@pytest.fixture(scope="module")
def policy():
    return PolicyEngine()


@pytest.fixture(scope="module")
def gate(policy):
    return AIReadinessGate(policy)


@pytest.fixture
def clean_inputs(policy):
    entity = PIIEntity(entity_type=EntityType.SSN, value="219-45-7890", confidence=0.95, page=1)
    policy_result = policy.apply([entity])
    return {
        "verifier_report": VerificationReport(units_scanned=1),
        "ocr_confidences": {1: 0.97, 2: 0.88},
        "policy_result": policy_result,
        "entities": [entity],
        "redaction_result": SimpleNamespace(unapplied_entity_ids=[], errors=[]),
        "input_safety_report": PromptSafetyReport(),
        "document_id": "doc-1",
    }


def _codes(decision):
    return [r.code for r in decision.reasons]


def _evaluate(gate, inputs):
    inputs = dict(inputs)
    return gate.evaluate(None, inputs.pop("verifier_report"), inputs.pop("ocr_confidences"), **inputs)


def test_all_conditions_met_passes(gate, clean_inputs):
    decision = _evaluate(gate, clean_inputs)
    assert decision.ai_ready
    assert decision.decision == "PASS"
    assert decision.status_code == PASS_STATUS
    assert decision.label == "AI READY: PASS"
    assert decision.inherent_risk == "CRITICAL"
    assert decision.residual_risk == "NONE"


def test_missing_verifier_blocks(gate, clean_inputs):
    clean_inputs["verifier_report"] = None
    decision = _evaluate(gate, clean_inputs)
    assert not decision.ai_ready
    assert "VERIFICATION_MISSING" in _codes(decision)
    assert decision.residual_risk == "CRITICAL"


def test_residual_finding_blocks(gate, clean_inputs):
    clean_inputs["verifier_report"] = IndependentVerifier.from_policy().verify_text("SSN 219-45-7890")
    decision = _evaluate(gate, clean_inputs)
    assert decision.status_code == "RESIDUAL_LEAK_DETECTED"
    assert "219-45-7890" not in str(decision.to_dict())


def test_uncertain_verifier_blocks(gate, clean_inputs):
    clean_inputs["verifier_report"] = VerificationReport(uncertain=True, errors=["x"], units_scanned=1)
    assert "VERIFIER_UNCERTAIN" in _codes(_evaluate(gate, clean_inputs))


def test_missing_policy_blocks(gate, clean_inputs):
    clean_inputs["policy_result"] = None
    assert "POLICY_NOT_APPLIED" in _codes(_evaluate(gate, clean_inputs))


def test_policy_block_blocks(gate, policy, clean_inputs):
    uncertain = PIIEntity(entity_type=EntityType.PASSPORT, value="K1234567", confidence=0.2, page=7)
    clean_inputs["policy_result"] = policy.apply([uncertain])
    clean_inputs["entities"] = [uncertain]
    decision = _evaluate(gate, clean_inputs)
    assert "POLICY_BLOCK" in _codes(decision)
    assert "CRITICAL_PII_PRESENT" in _codes(decision)


def test_unredacted_entity_blocks(gate, clean_inputs):
    clean_inputs["entities"][0].action = Action.REVIEW
    assert "CRITICAL_PII_PRESENT" in _codes(_evaluate(gate, clean_inputs))


def test_incomplete_redaction_blocks(gate, clean_inputs):
    clean_inputs["redaction_result"] = SimpleNamespace(unapplied_entity_ids=["e1"], errors=[])
    assert "REDACTION_INCOMPLETE" in _codes(_evaluate(gate, clean_inputs))


@pytest.mark.parametrize("confidence", [0.60, 0.35, None, float("nan"), "bad"])
def test_low_ocr_confidence_blocks(gate, clean_inputs, confidence):
    clean_inputs["ocr_confidences"] = {1: 0.95, 22: confidence}
    decision = _evaluate(gate, clean_inputs)
    assert "LOW_CONFIDENCE_UNCERTAINTY" in _codes(decision)
    assert "22" in decision.reasons[-1].detail


def test_prompt_injection_blocks(gate, clean_inputs):
    clean_inputs["input_safety_report"] = PromptSafetyReport(
        is_suspicious=True, injections_detected=["ignore previous"], risk_level="HIGH"
    )
    assert "PROMPT_INJECTION_DETECTED" in _codes(_evaluate(gate, clean_inputs))


def test_unicode_anomalies_alone_do_not_block_by_default(gate, clean_inputs):
    clean_inputs["input_safety_report"] = PromptSafetyReport(unicode_anomalies=["ZERO WIDTH SPACE (count: 1)"])
    assert _evaluate(gate, clean_inputs).ai_ready


def test_failed_integrity_blocks(gate, clean_inputs):
    clean_inputs["integrity_result"] = IntegrityCheckResult(False, "x.docx", ".docx", error="CRC failed")
    assert "INTEGRITY_CHECK_FAILED" in _codes(_evaluate(gate, clean_inputs))


def test_pipeline_errors_block(gate, clean_inputs):
    clean_inputs["pipeline_errors"] = ["OCR engine crashed on page 4"]
    assert _evaluate(gate, clean_inputs).status_code == "PIPELINE_ERROR"


def test_reasons_accumulate(gate, clean_inputs):
    clean_inputs["verifier_report"] = None
    clean_inputs["ocr_confidences"] = {3: 0.1}
    codes = _codes(_evaluate(gate, clean_inputs))
    assert {"VERIFICATION_MISSING", "LOW_CONFIDENCE_UNCERTAINTY"} <= set(codes)


def test_internal_error_fails_closed(gate, clean_inputs):
    clean_inputs["ocr_confidences"] = SimpleNamespace()  # no .items() -> crash inside the gate
    decision = _evaluate(gate, clean_inputs)
    assert decision.decision == "BLOCK"
    assert decision.status_code == "GATE_INTERNAL_ERROR"


def test_prd_signature_with_canonical_document(gate, policy):
    doc = CanonicalDocument(doc_id="doc-22", source_path="x", filename="x.pdf", file_type=".pdf",
                            pages=2, ocr_confidence={1: 0.95, 2: 0.91})
    doc.entities = [EntityAnnotation.create("EMAIL", "a@b.com", source="regex", page=1, confidence=0.9)]
    policy_result = policy.apply_to_document(doc)
    decision = gate.evaluate(doc, VerificationReport(units_scanned=2), policy_result=policy_result)
    assert decision.ai_ready
    assert decision.document_id == "doc-22"


def test_ceiling_can_be_relaxed_only_by_policy(clean_inputs):
    import copy, yaml
    from src.policy.policy import DEFAULT_POLICY_PATH, PolicyConfig

    data = yaml.safe_load(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"))
    data = copy.deepcopy(data)
    data["gate"]["max_allowed_residual_risk"] = "MEDIUM"
    relaxed = AIReadinessGate(PolicyConfig.from_dict(data))
    clean_inputs["verifier_report"] = IndependentVerifier.from_policy().verify_text("IFSC SBIN0001234")
    assert _evaluate(relaxed, clean_inputs).ai_ready
