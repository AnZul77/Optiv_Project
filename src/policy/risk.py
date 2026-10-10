"""
Risk Model: Inherent vs. Residual Risk (Critical Dominance)
===========================================================

Inherent risk = the worst risk among the PII found BEFORE redaction.
    One SSN anywhere in a 35-page document makes the document CRITICAL.

Residual risk = the worst risk that REMAINS after redaction + verification.
    It is NONE only when every finding was redacted (or allow-listed) and the
    independent verifier saw nothing. Anything we cannot vouch for counts.

The helpers at the bottom (entity_type_name, ...) let every Person 4 module
accept both entity shapes used in the repo:
    - src.schema.entities.PIIEntity           (Person 3: entity_type / risk_level enums)
    - src.schema.document.EntityAnnotation    (Person 1: type / risk / action strings)

**Ownership:** Person 4 (Security Policy, Independent Verification & Audit)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Optional

RISK_ORDER: Dict[str, int] = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Unknown risk labels are treated as HIGH (matches schema DEFAULT_RISK_LEVEL).
DEFAULT_UNKNOWN_RISK = "HIGH"

# Entity actions that mean "this PII is not going downstream as-is".
RESOLVED_ACTIONS = frozenset({"REDACT", "ALLOW"})


def _enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def normalize_risk(value: Any) -> str:
    """Return a canonical risk label; unknown or empty labels become HIGH."""
    label = str(_enum_value(value) or "").strip().upper()
    return label if label in RISK_ORDER else DEFAULT_UNKNOWN_RISK


def risk_rank(value: Any) -> int:
    return RISK_ORDER[normalize_risk(value)]


def max_risk(values: Iterable[Any]) -> str:
    """Critical dominance: the single worst risk wins. Empty input -> NONE."""
    worst = "NONE"
    for value in values:
        label = normalize_risk(value)
        if RISK_ORDER[label] > RISK_ORDER[worst]:
            worst = label
    return worst


def risk_exceeds(value: Any, ceiling: Any) -> bool:
    """True when `value` is strictly worse than the allowed `ceiling`."""
    return risk_rank(value) > risk_rank(ceiling)


# =============================================================================
# Entity adapters (PIIEntity <-> EntityAnnotation)
# =============================================================================

def entity_type_name(entity: Any) -> str:
    raw = getattr(entity, "entity_type", None)
    if raw is None:
        raw = getattr(entity, "type", "")
    return str(_enum_value(raw) or "").strip().upper()


def entity_risk_name(entity: Any) -> str:
    raw = getattr(entity, "risk_level", None)
    if raw is None:
        raw = getattr(entity, "risk", None)
    return normalize_risk(raw)


def entity_action_name(entity: Any) -> str:
    return str(_enum_value(getattr(entity, "action", "")) or "").strip().upper()


def entity_block_id(entity: Any) -> str:
    """Block reference: PIIEntity.block_id, or EntityAnnotation.context['block_id']."""
    block_id = getattr(entity, "block_id", "") or ""
    if not block_id:
        context = getattr(entity, "context", None)
        if isinstance(context, dict):
            block_id = context.get("block_id", "") or ""
    return str(block_id)


# =============================================================================
# Inherent / residual risk
# =============================================================================

def inherent_risk(entities: Iterable[Any], exclude_allowed: bool = True) -> str:
    """Worst risk among detected PII before redaction (allow-listed codes are not PII)."""
    return max_risk(
        entity_risk_name(e)
        for e in entities
        if not (exclude_allowed and entity_action_name(e) == "ALLOW")
    )


def residual_risk(
    entities: Iterable[Any],
    verification_report: Optional[Any] = None,
    unapplied_entity_ids: Iterable[str] = (),
    require_verification: bool = True,
) -> str:
    """
    Risk left after redaction and verification.

    Contributors:
        * entities whose action is not REDACT/ALLOW (BLOCK, REVIEW, unknown)
        * entities the redactor could not apply (offset/block mapping failed)
        * independent verifier findings
        * a missing or uncertain verification -> CRITICAL (unknown is unsafe)
    """
    unapplied = set(unapplied_entity_ids)
    contributors = []

    for entity in entities:
        action = entity_action_name(entity)
        if action not in RESOLVED_ACTIONS or getattr(entity, "entity_id", None) in unapplied:
            contributors.append(entity_risk_name(entity))

    if verification_report is None:
        if require_verification:
            contributors.append("CRITICAL")
    else:
        if getattr(verification_report, "uncertain", False):
            contributors.append("CRITICAL")
        contributors.extend(
            getattr(finding, "risk", "CRITICAL")
            for finding in getattr(verification_report, "findings", [])
        )

    return max_risk(contributors)


@dataclass
class RiskAssessment:
    """Inherent and residual risk for one document, with per-level counts."""

    inherent: str = "NONE"
    residual: str = "NONE"
    entity_counts: Dict[str, int] = field(default_factory=dict)

    @classmethod
    def assess(
        cls,
        entities: Iterable[Any],
        verification_report: Optional[Any] = None,
        unapplied_entity_ids: Iterable[str] = (),
    ) -> "RiskAssessment":
        entities = list(entities)
        counts: Dict[str, int] = {}
        for entity in entities:
            label = entity_risk_name(entity)
            counts[label] = counts.get(label, 0) + 1
        return cls(
            inherent=inherent_risk(entities),
            residual=residual_risk(entities, verification_report, unapplied_entity_ids),
            entity_counts=counts,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "inherent_risk": self.inherent,
            "residual_risk": self.residual,
            "entity_counts": dict(self.entity_counts),
        }
