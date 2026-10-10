"""
Fail-Closed AI Readiness Gate
=============================

The last check before anything reaches an LLM. The decision is PASS only if
EVERY condition below holds; anything missing, failing, or erroring is BLOCK.

    1. The independent verifier ran, was certain, and found nothing
       above gate.max_allowed_residual_risk (default NONE)
    2. The policy engine ran and did not BLOCK the document
    3. No entity is left un-redacted (action other than REDACT / ALLOW)
    4. The text redactor applied every redaction it was given
    5. Every page's OCR confidence is above gate.min_page_ocr_confidence
    6. Input safety report is clean (prompt injection -> BLOCK by default)
    7. Sanitized-file integrity check passed (when a file was produced)
    8. No upstream pipeline errors

Block codes follow the failure table in docs/architecture.md.

**Ownership:** Person 4 (Security Policy, Independent Verification & Audit)
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional

from src.policy.policy import PolicyConfig
from src.policy.risk import (
    RESOLVED_ACTIONS,
    entity_action_name,
    entity_risk_name,
    entity_type_name,
    inherent_risk,
    max_risk,
    residual_risk,
    risk_exceeds,
)

PASS = "PASS"
BLOCK = "BLOCK"
PASS_STATUS = "DOCUMENT_SANITIZED_AND_VERIFIED"


@dataclass
class GateReason:
    code: str
    detail: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {"code": self.code, "detail": self.detail}


@dataclass
class GateDecision:
    document_id: str
    decision: str
    reasons: List[GateReason] = field(default_factory=list)
    inherent_risk: str = "NONE"
    residual_risk: str = "NONE"
    policy_version: str = ""
    evaluated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    @property
    def ai_ready(self) -> bool:
        return self.decision == PASS

    @property
    def status_code(self) -> str:
        return PASS_STATUS if self.ai_ready else (self.reasons[0].code if self.reasons else "BLOCKED")

    @property
    def label(self) -> str:
        """Banner text for the UI: 'AI READY: PASS' / 'AI READY: BLOCK'."""
        return f"AI READY: {self.decision}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "document_id": self.document_id,
            "decision": self.decision,
            "ai_ready": self.ai_ready,
            "status_code": self.status_code,
            "reasons": [r.to_dict() for r in self.reasons],
            "inherent_risk": self.inherent_risk,
            "residual_risk": self.residual_risk,
            "policy_version": self.policy_version,
            "evaluated_at": self.evaluated_at,
        }


def _safe_confidence(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) else 0.0


def _type_page_summary(items: Iterable[Any], type_attr: str = "entity_type") -> str:
    """'SSN p.2, EMAIL p.3' style summary. Types and pages only, never values."""
    parts = []
    for item in items:
        etype = getattr(item, type_attr, None) or entity_type_name(item)
        parts.append(f"{etype} p.{getattr(item, 'page', '?')}")
    return ", ".join(parts[:10]) + (f" (+{len(parts) - 10} more)" if len(parts) > 10 else "")


class AIReadinessGate:
    """Fail-closed PASS / BLOCK decision for one document."""

    def __init__(self, policy: Any = None):
        config = getattr(policy, "config", policy) if policy is not None else PolicyConfig.load()
        self.config: PolicyConfig = config
        self.settings = config.gate

    def evaluate(
        self,
        document: Any = None,
        verifier_report: Any = None,
        ocr_confidences: Optional[Mapping[int, Any]] = None,
        *,
        policy_result: Any = None,
        entities: Optional[Iterable[Any]] = None,
        redaction_result: Any = None,
        input_safety_report: Any = None,
        integrity_result: Any = None,
        pipeline_errors: Optional[Iterable[str]] = None,
        document_id: Optional[str] = None,
    ) -> GateDecision:
        """
        Args:
            document:            CanonicalDocument (optional; supplies doc_id, entities,
                                 and per-page ocr_confidence when the others are omitted).
            verifier_report:     VerificationReport from IndependentVerifier (REQUIRED).
            ocr_confidences:     {page_num: confidence}; defaults to document.ocr_confidence.
            policy_result:       PolicyResult from PolicyEngine.apply() (REQUIRED).
            entities:            Entities after policy (defaults to document.entities).
            redaction_result:    BlockRedactionResult / TextRedactionResult from TextRedactor.
            input_safety_report: PromptSafetyReport from Person 1's InputSafetyGuard.
            integrity_result:    IntegrityCheckResult from Person 1's DocumentIntegrityGuard.
            pipeline_errors:     Errors raised upstream (extraction, OCR, detection).
        """
        doc_id = document_id or str(getattr(document, "doc_id", "") or "")
        try:
            return self._evaluate(
                doc_id, document, verifier_report, ocr_confidences, policy_result, entities,
                redaction_result, input_safety_report, integrity_result, pipeline_errors,
            )
        except Exception as exc:  # the gate itself must never fail open
            return self.block_on_error(doc_id, exc)

    def block_on_error(self, document_id: str, error: Any, code: str = "GATE_INTERNAL_ERROR") -> GateDecision:
        detail = type(error).__name__ if isinstance(error, BaseException) else str(error)
        return GateDecision(
            document_id=document_id,
            decision=BLOCK,
            reasons=[GateReason(code, detail)],
            residual_risk="CRITICAL",
            policy_version=self.config.version,
        )

    # ------------------------------------------------------------------ internals
    def _evaluate(
        self, doc_id, document, verifier_report, ocr_confidences, policy_result, entities,
        redaction_result, input_safety_report, integrity_result, pipeline_errors,
    ) -> GateDecision:
        ceiling = self.settings["max_allowed_residual_risk"]
        reasons: List[GateReason] = []
        if entities is None:
            entities = getattr(document, "entities", None) or []
        entities = list(entities)

        # 8. Upstream errors
        errors = [e for e in (pipeline_errors or []) if e]
        if errors:
            reasons.append(GateReason("PIPELINE_ERROR", "; ".join(str(e) for e in errors[:5])))

        # 2. Policy
        if policy_result is None:
            reasons.append(GateReason("POLICY_NOT_APPLIED", "no PolicyResult supplied"))
        elif getattr(policy_result, "document_action", BLOCK) == BLOCK:
            detail = "; ".join(getattr(policy_result, "block_reasons", [])[:5]) or "policy returned BLOCK"
            reasons.append(GateReason("POLICY_BLOCK", detail))

        # 3. Un-redacted entities
        unresolved = [e for e in entities if entity_action_name(e) not in RESOLVED_ACTIONS]
        unresolved_risk = max_risk(entity_risk_name(e) for e in unresolved)
        if unresolved and risk_exceeds(unresolved_risk, ceiling):
            code = "CRITICAL_PII_PRESENT" if unresolved_risk == "CRITICAL" else "UNREDACTED_PII_PRESENT"
            reasons.append(GateReason(code, _type_page_summary(unresolved)))

        # 4. Redaction completeness
        unapplied: List[str] = []
        if redaction_result is not None:
            unapplied = list(getattr(redaction_result, "unapplied_entity_ids", []) or [])
            redaction_errors = list(getattr(redaction_result, "errors", []) or [])
            if unapplied or redaction_errors:
                reasons.append(GateReason(
                    "REDACTION_INCOMPLETE",
                    f"{len(unapplied)} entities not applied; {len(redaction_errors)} errors",
                ))

        # 1. Independent verification
        if verifier_report is None:
            reasons.append(GateReason("VERIFICATION_MISSING", "independent verifier did not run"))
        else:
            findings = list(getattr(verifier_report, "findings", []) or [])
            finding_risk = max_risk(getattr(f, "risk", "CRITICAL") for f in findings)
            if findings and risk_exceeds(finding_risk, ceiling):
                reasons.append(GateReason(
                    "RESIDUAL_LEAK_DETECTED",
                    f"{len(findings)} residual findings: {_type_page_summary(findings)}",
                ))
            if getattr(verifier_report, "uncertain", False) or getattr(verifier_report, "errors", None):
                reasons.append(GateReason(
                    "VERIFIER_UNCERTAIN",
                    "; ".join(getattr(verifier_report, "errors", [])[:3]) or "verifier uncertain",
                ))

        # 5. OCR confidence
        if ocr_confidences is None:
            ocr_confidences = getattr(document, "ocr_confidence", None) or {}
        threshold = self.settings["min_page_ocr_confidence"]
        low_pages = sorted(
            int(p) for p, c in ocr_confidences.items() if _safe_confidence(c) <= threshold
        )
        if low_pages:
            reasons.append(GateReason(
                "LOW_CONFIDENCE_UNCERTAINTY",
                f"OCR confidence <= {threshold:.2f} on pages {low_pages[:20]}",
            ))

        # 6. Input safety (Person 1's PromptSafetyReport)
        if input_safety_report is not None:
            if self.settings.get("block_on_prompt_injection", True) and \
                    getattr(input_safety_report, "injections_detected", None):
                reasons.append(GateReason(
                    "PROMPT_INJECTION_DETECTED",
                    f"{len(input_safety_report.injections_detected)} injection patterns matched",
                ))
            if self.settings.get("block_on_unicode_anomalies", False) and \
                    getattr(input_safety_report, "unicode_anomalies", None):
                reasons.append(GateReason(
                    "UNICODE_ANOMALY_DETECTED",
                    "; ".join(input_safety_report.unicode_anomalies[:3]),
                ))

        # 7. Integrity of the sanitized file (Person 1's DocumentIntegrityGuard)
        if integrity_result is not None:
            if not getattr(integrity_result, "is_valid", False):
                reasons.append(GateReason(
                    "INTEGRITY_CHECK_FAILED", str(getattr(integrity_result, "error", "") or "")
                ))
        elif self.settings.get("require_integrity_check", False):
            reasons.append(GateReason("INTEGRITY_CHECK_MISSING", "no integrity result supplied"))

        residual = residual_risk(entities, verifier_report, unapplied)
        if not reasons and risk_exceeds(residual, ceiling):
            reasons.append(GateReason("RESIDUAL_RISK_EXCEEDED", f"residual {residual} > {ceiling}"))

        return GateDecision(
            document_id=doc_id,
            decision=BLOCK if reasons else PASS,
            reasons=reasons,
            inherent_risk=(getattr(policy_result, "inherent_risk", None) or inherent_risk(entities)),
            residual_risk=residual,
            policy_version=self.config.version,
        )
