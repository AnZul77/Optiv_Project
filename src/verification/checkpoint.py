"""
Security Checkpoint (Person 4 orchestration)
============================================

Runs the Person 4 half of the pipeline on Person 3's output:

    ContentBlocks + DetectionResult (Person 3)
        -> PolicyEngine        (REDACT / BLOCK / ALLOW per entity)
        -> TextRedactor        ([REDACTED_TYPE] in every block)
        -> IndependentVerifier (re-scan sanitized blocks, different stack)
        -> + residual re-OCR reports (optional, from ResidualScanner)
        -> InputSafetyGuard    (Person 1: prompt-injection scan + inert envelope)
        -> AIReadinessGate     (fail-closed PASS / BLOCK)
        -> AuditLogger         (zero-PII trail)

    checkpoint = SecurityCheckpoint()
    result = checkpoint.run(blocks, detection_result, filename="policy.pdf")
    result.ai_ready        # True only on PASS
    result.llm_payload     # sanitized text in an inert envelope; None when blocked

Anything that raises along the way (including the audit write) turns into
BLOCK; nothing here can fail open.

**Ownership:** Person 4 (Security Policy, Independent Verification & Audit)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from src.policy.policy import PolicyEngine, PolicyResult
from src.policy.risk import RiskAssessment
from src.sanitization.text_redactor import BlockRedactionResult, TextRedactor
from src.security.input_safety import InputSafetyGuard
from src.verification.gate import AIReadinessGate, GateDecision
from src.verification.verifier import IndependentVerifier, VerificationReport


@dataclass
class CheckpointResult:
    document_id: str
    filename: str
    gate_decision: GateDecision
    policy_result: Optional[PolicyResult] = None
    redaction: Optional[BlockRedactionResult] = None
    verification_report: Optional[VerificationReport] = None
    risk: Optional[RiskAssessment] = None
    llm_payload: Optional[str] = None
    audit_records_written: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def ai_ready(self) -> bool:
        return self.gate_decision.ai_ready

    @property
    def sanitized_blocks(self) -> List[Any]:
        """Sanitized blocks, released only when the gate passed."""
        return self.redaction.sanitized_blocks if (self.ai_ready and self.redaction) else []

    def to_dict(self) -> Dict[str, Any]:
        """UI / API summary. Contains no raw PII."""
        return {
            "document_id": self.document_id,
            "filename": self.filename,
            "gate": self.gate_decision.to_dict(),
            "policy": self.policy_result.to_dict() if self.policy_result else None,
            "verification": self.verification_report.to_dict() if self.verification_report else None,
            "risk": self.risk.to_dict() if self.risk else None,
            "redactions_applied": self.redaction.redaction_count if self.redaction else 0,
            "audit_records_written": self.audit_records_written,
            "errors": list(self.errors),
        }


class SecurityCheckpoint:
    """Policy -> redaction -> independent verification -> gate -> audit."""

    def __init__(
        self,
        policy: Optional[PolicyEngine] = None,
        verifier: Optional[IndependentVerifier] = None,
        gate: Optional[AIReadinessGate] = None,
        redactor: Optional[TextRedactor] = None,
        audit_logger: Any = None,
        enable_audit: bool = True,
        input_guard: Optional[InputSafetyGuard] = None,
    ):
        self.policy = policy or PolicyEngine()
        self.verifier = verifier or IndependentVerifier.from_policy(self.policy)
        self.gate = gate or AIReadinessGate(self.policy)
        self.redactor = redactor or TextRedactor.from_policy(self.policy)
        self.input_guard = input_guard or InputSafetyGuard()
        if audit_logger is None and enable_audit:
            from src.audit.logger import AuditLogger
            audit_logger = AuditLogger.from_policy(self.policy)
        self.audit_logger = audit_logger if enable_audit else None

    def run(
        self,
        blocks: Sequence[Any],
        detection: Any,
        document_id: Optional[str] = None,
        filename: str = "",
        ocr_confidences: Optional[Mapping[int, Any]] = None,
        residual_reports: Iterable[VerificationReport] = (),
        integrity_result: Any = None,
        pipeline_errors: Iterable[str] = (),
    ) -> CheckpointResult:
        """
        Args:
            blocks:           ContentBlocks the detector ran on (`.block_id`, `.text`, `.page`).
            detection:        Person 3 DetectionResult, or a plain list of entities.
            document_id:      Defaults to detection.document_id or a new UUID.
            ocr_confidences:  {page: confidence} for OCR'd pages.
            residual_reports: ResidualScanner reports for burned images / PDF pages.
            integrity_result: DocumentIntegrityGuard result for a reconstructed file.
            pipeline_errors:  Upstream errors to surface in the gate decision.
        """
        document_id = document_id or getattr(detection, "document_id", "") or f"doc-{uuid.uuid4()}"
        filename = filename or getattr(detection, "source_file", "") or ""
        entities = list(getattr(detection, "entities", detection) or [])
        result = CheckpointResult(
            document_id=document_id,
            filename=filename,
            gate_decision=self.gate.block_on_error(document_id, "checkpoint did not complete",
                                                   code="CHECKPOINT_INCOMPLETE"),
        )

        try:
            result.policy_result = self.policy.apply(entities)
            result.redaction = self.redactor.redact_blocks(blocks, entities)

            report = self.verifier.verify_blocks(result.redaction.sanitized_blocks)
            for residual in residual_reports:
                report = report.merge(residual)
            result.verification_report = report

            payload, safety_report = self.input_guard.isolate_for_llm_consumption(
                result.redaction.sanitized_text, document_id=document_id
            )

            result.gate_decision = self.gate.evaluate(
                None,
                report,
                ocr_confidences or {},
                policy_result=result.policy_result,
                entities=entities,
                redaction_result=result.redaction,
                input_safety_report=safety_report,
                integrity_result=integrity_result,
                pipeline_errors=list(pipeline_errors),
                document_id=document_id,
            )
            result.risk = RiskAssessment.assess(
                entities, report, result.redaction.unapplied_entity_ids
            )
            if result.gate_decision.ai_ready:
                result.llm_payload = payload
        except Exception as exc:
            result.errors.append(f"checkpoint error: {type(exc).__name__}")
            result.gate_decision = self.gate.block_on_error(document_id, exc, code="PIPELINE_ERROR")
            result.llm_payload = None

        if self.audit_logger is not None:
            try:
                result.audit_records_written = self.audit_logger.log_document(
                    document_id, filename, entities, result.gate_decision,
                    result.policy_result, result.verification_report,
                )
            except Exception as exc:  # no audit trail -> no release
                result.errors.append(f"audit error: {type(exc).__name__}")
                result.gate_decision = self.gate.block_on_error(document_id, exc, code="AUDIT_LOG_FAILURE")
                result.llm_payload = None

        return result
