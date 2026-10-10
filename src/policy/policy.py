"""
Policy Engine: config/policy.yaml -> REDACT / BLOCK / ALLOW per entity
======================================================================

Takes the resolved entities from Person 3's detection pipeline and assigns
each one an action, using the risk tiers and allow-lists in config/policy.yaml.

    engine = PolicyEngine()                      # loads config/policy.yaml
    result = engine.apply(detection_result.entities)
    result.document_action   # "BLOCK" | "REDACT" | "ALLOW"
    result.inherent_risk     # critical dominance: one SSN -> "CRITICAL"

Decision per entity:
    1. Value fully matches an allow-list pattern  -> ALLOW (business code, not PII)
    2. Effective risk = max(policy tier, schema RISK_MAPPING, detector's risk)
       (the policy can escalate risk, never downgrade it)
    3. confidence >= tier.min_confidence_to_redact -> tier.action
       confidence <  tier.min_confidence_to_redact -> tier.uncertainty_action
       (CRITICAL uses BLOCK here: an uncertain SSN stops the document)

A config that is missing, malformed, or tries to weaken the fail-closed
stance raises PolicyConfigError; callers must treat that as BLOCK.

**Ownership:** Person 4 (Security Policy, Independent Verification & Audit)
"""

from __future__ import annotations

import copy
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import yaml

from src.policy.risk import (
    RISK_ORDER,
    entity_risk_name,
    entity_type_name,
    max_risk,
    normalize_risk,
)
from src.schema.entities import RISK_MAPPING

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = PROJECT_ROOT / "config" / "policy.yaml"

TIERS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
VALID_ACTIONS = frozenset({"REDACT", "BLOCK", "ALLOW"})
UNCERTAINTY_ACTIONS = frozenset({"REDACT", "BLOCK"})
ALLOW_PERMITTED_TIERS = frozenset({"MEDIUM", "LOW"})

# Fallbacks for keys missing from policy.yaml (kept in sync with the shipped file).
SECTION_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "redaction": {
        "mode": "token",
        "token_format": "[REDACTED_{type}]",
        "block_char": "█",
        "min_docx_target_length": 3,
    },
    "verification": {
        "digit_run_min_length": 9,
        "digit_run_max_length": 19,
        "digit_entropy_threshold": 2.5,
        "spacing_min_run": 4,
        "cue_window_chars": 30,
        "residual_scan": {
            "burned_box_overlap_threshold": 0.30,
            "min_reocr_confidence": 0.60,
        },
    },
    "gate": {
        "fail_closed": True,
        "max_allowed_residual_risk": "NONE",
        "min_page_ocr_confidence": 0.60,
        "block_on_prompt_injection": True,
        "block_on_unicode_anomalies": False,
        "require_integrity_check": False,
    },
    "audit": {
        "log_path": "data/outputs/audit.log",
        "salt_env_var": "PII_FIREWALL_AUDIT_SALT",
        "hash_filenames": False,
        "hash_chain": True,
    },
}


class PolicyConfigError(ValueError):
    """policy.yaml is missing, malformed, or weakens the fail-closed stance."""


def _deep_merge(base: Dict[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _as_unit_float(value: Any, where: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise PolicyConfigError(f"{where} must be a number between 0 and 1, got {value!r}")
    if math.isnan(number) or not 0.0 <= number <= 1.0:
        raise PolicyConfigError(f"{where} must be between 0 and 1, got {value!r}")
    return number


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class TierRule:
    risk: str
    entities: List[str]
    action: str = "REDACT"
    min_confidence_to_redact: float = 0.0
    uncertainty_action: str = "REDACT"


@dataclass
class PolicyConfig:
    version: str
    name: str
    tiers: Dict[str, TierRule]
    unknown_risk: str
    unknown_action: str
    allow_list_patterns: List[str]
    redaction: Dict[str, Any]
    verification: Dict[str, Any]
    gate: Dict[str, Any]
    audit: Dict[str, Any]
    source_path: str = ""
    _type_to_tier: Dict[str, str] = field(default_factory=dict, repr=False)

    @classmethod
    def load(cls, path: Optional[str | Path] = None) -> "PolicyConfig":
        policy_path = Path(path) if path else DEFAULT_POLICY_PATH
        if not policy_path.is_file():
            raise PolicyConfigError(f"Policy file not found: {policy_path}")
        try:
            data = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise PolicyConfigError(f"Policy file is not valid YAML: {exc}") from exc
        return cls.from_dict(data, source_path=str(policy_path))

    @classmethod
    def from_dict(cls, data: Any, source_path: str = "") -> "PolicyConfig":
        if not isinstance(data, Mapping):
            raise PolicyConfigError("Policy must be a mapping at the top level")

        rules = data.get("rules")
        if not isinstance(rules, Mapping) or not rules:
            raise PolicyConfigError("Policy must define a non-empty 'rules' section")

        unknown_tiers = set(rules) - set(TIERS)
        if unknown_tiers:
            raise PolicyConfigError(f"Unknown risk tiers in rules: {sorted(unknown_tiers)}")

        tiers: Dict[str, TierRule] = {}
        type_to_tier: Dict[str, str] = {}
        for tier in TIERS:
            raw = rules.get(tier) or {}
            where = f"rules.{tier}"

            action = str(raw.get("action", "REDACT")).upper()
            if action not in VALID_ACTIONS:
                raise PolicyConfigError(f"{where}.action must be one of {sorted(VALID_ACTIONS)}")
            if action == "ALLOW" and tier not in ALLOW_PERMITTED_TIERS:
                raise PolicyConfigError(f"{where}.action cannot be ALLOW for {tier} risk")

            uncertainty = str(raw.get("uncertainty_action", "REDACT")).upper()
            if uncertainty not in UNCERTAINTY_ACTIONS:
                raise PolicyConfigError(
                    f"{where}.uncertainty_action must be one of {sorted(UNCERTAINTY_ACTIONS)}"
                )

            entities = [str(e).strip().upper() for e in (raw.get("entities") or [])]
            for entity_type in entities:
                if entity_type in type_to_tier:
                    raise PolicyConfigError(
                        f"{entity_type} is listed in both {type_to_tier[entity_type]} and {tier}"
                    )
                type_to_tier[entity_type] = tier

            tiers[tier] = TierRule(
                risk=tier,
                entities=entities,
                action=action,
                min_confidence_to_redact=_as_unit_float(
                    raw.get("min_confidence_to_redact", 0.0), f"{where}.min_confidence_to_redact"
                ),
                uncertainty_action=uncertainty,
            )

        unknown = data.get("unknown_entity_policy") or {}
        unknown_risk = str(unknown.get("risk", "HIGH")).upper()
        if unknown_risk not in RISK_ORDER or unknown_risk == "NONE":
            raise PolicyConfigError("unknown_entity_policy.risk must be LOW, MEDIUM, HIGH or CRITICAL")
        unknown_action = str(unknown.get("action", "REDACT")).upper()
        if unknown_action not in UNCERTAINTY_ACTIONS:
            raise PolicyConfigError("unknown_entity_policy.action must be REDACT or BLOCK")

        patterns: List[str] = []
        for group, entries in (data.get("allow_lists") or {}).items():
            for pattern in entries or []:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise PolicyConfigError(f"allow_lists.{group}: invalid regex {pattern!r}: {exc}")
                patterns.append(pattern)

        sections = {
            name: _deep_merge(defaults, data.get(name) or {})
            for name, defaults in SECTION_DEFAULTS.items()
        }

        gate = sections["gate"]
        if gate.get("fail_closed") is not True:
            raise PolicyConfigError("gate.fail_closed must be true; the firewall never fails open")
        residual_ceiling = str(gate.get("max_allowed_residual_risk", "NONE")).upper()
        if residual_ceiling not in RISK_ORDER:
            raise PolicyConfigError("gate.max_allowed_residual_risk must be a valid risk level")
        gate["max_allowed_residual_risk"] = residual_ceiling
        gate["min_page_ocr_confidence"] = _as_unit_float(
            gate.get("min_page_ocr_confidence"), "gate.min_page_ocr_confidence"
        )

        if sections["redaction"].get("mode") not in ("token", "block"):
            raise PolicyConfigError("redaction.mode must be 'token' or 'block'")

        return cls(
            version=str(data.get("version", "")),
            name=str(data.get("policy_name", "")),
            tiers=tiers,
            unknown_risk=unknown_risk,
            unknown_action=unknown_action,
            allow_list_patterns=patterns,
            redaction=sections["redaction"],
            verification=sections["verification"],
            gate=gate,
            audit=sections["audit"],
            source_path=source_path,
            _type_to_tier=type_to_tier,
        )

    def tier_for_type(self, entity_type: str) -> Optional[str]:
        return self._type_to_tier.get(entity_type.upper())

    def resolve_path(self, relative: str) -> Path:
        """Resolve a config path (e.g. audit.log_path) against the repo root."""
        path = Path(relative)
        return path if path.is_absolute() else PROJECT_ROOT / path


def load_policy(path: Optional[str | Path] = None) -> PolicyConfig:
    return PolicyConfig.load(path)


# =============================================================================
# Decisions
# =============================================================================

@dataclass
class PolicyDecision:
    """Outcome for one entity. Contains no raw PII."""

    entity_id: str
    entity_type: str
    page: int
    risk: str
    action: str
    confidence: float
    reason: str
    allow_listed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "page": self.page,
            "risk": self.risk,
            "action": self.action,
            "confidence": round(self.confidence, 4),
            "reason": self.reason,
            "allow_listed": self.allow_listed,
        }


@dataclass
class PolicyResult:
    decisions: List[PolicyDecision] = field(default_factory=list)
    document_action: str = "ALLOW"
    inherent_risk: str = "NONE"
    block_reasons: List[str] = field(default_factory=list)
    policy_version: str = ""

    @property
    def is_blocked(self) -> bool:
        return self.document_action == "BLOCK"

    @property
    def action_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for decision in self.decisions:
            counts[decision.action] = counts.get(decision.action, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "document_action": self.document_action,
            "inherent_risk": self.inherent_risk,
            "action_counts": self.action_counts,
            "block_reasons": list(self.block_reasons),
            "decisions": [d.to_dict() for d in self.decisions],
        }


# =============================================================================
# Engine
# =============================================================================

def _safe_confidence(value: Any) -> float:
    """Missing / NaN / out-of-range confidence is treated as 0.0 (uncertain)."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(number):
        return 0.0
    return max(0.0, min(1.0, number))


def _set_entity_fields(entity: Any, action: str, risk: str, decision: PolicyDecision) -> None:
    """Write the decision back onto the entity, preserving its native field types."""
    current_action = getattr(entity, "action", None)
    if isinstance(current_action, Enum):
        entity.action = type(current_action)(action)
    else:
        entity.action = action

    if hasattr(entity, "risk_level"):
        current_risk = entity.risk_level
        entity.risk_level = type(current_risk)(risk) if isinstance(current_risk, Enum) else risk
    elif hasattr(entity, "risk"):
        entity.risk = risk

    context = getattr(entity, "context", None)
    if isinstance(context, dict):
        context["policy"] = {"reason": decision.reason, "allow_listed": decision.allow_listed}


class PolicyEngine:
    """Assigns REDACT / BLOCK / ALLOW to detected entities per config/policy.yaml."""

    def __init__(
        self,
        config: Optional[PolicyConfig] = None,
        policy_path: Optional[str | Path] = None,
    ):
        self.config = config or PolicyConfig.load(policy_path)
        self._allow_list = [re.compile(p) for p in self.config.allow_list_patterns]

    # ------------------------------------------------------------------ allow-list
    def is_allow_listed(self, value: Optional[str]) -> bool:
        if not value:
            return False
        candidate = value.strip()
        return any(p.fullmatch(candidate) for p in self._allow_list)

    def find_allow_listed_spans(self, text: str) -> List[Tuple[int, int]]:
        spans = []
        for pattern in self._allow_list:
            spans.extend(m.span() for m in pattern.finditer(text or ""))
        return sorted(spans)

    # ------------------------------------------------------------------ risk
    def effective_risk(self, entity_type: str, detector_risk: Any = None) -> str:
        """max(policy tier, schema RISK_MAPPING, detector-assigned risk)."""
        entity_type = entity_type.upper()
        candidates = [self.config.tier_for_type(entity_type) or self.config.unknown_risk]
        for schema_type, schema_risk in RISK_MAPPING.items():
            if schema_type.value == entity_type:
                candidates.append(schema_risk.value)
                break
        if detector_risk is not None:
            candidates.append(normalize_risk(detector_risk))
        risk = max_risk(candidates)
        # NONE is not a tier; anything detected is at least LOW.
        return "LOW" if risk == "NONE" else risk

    # ------------------------------------------------------------------ decisions
    def evaluate_entity(self, entity: Any, raw_value: Optional[str] = None) -> PolicyDecision:
        entity_type = entity_type_name(entity) or "UNKNOWN"
        confidence = _safe_confidence(getattr(entity, "confidence", 0.0))
        entity_id = str(getattr(entity, "entity_id", ""))
        page = int(getattr(entity, "page", 0) or 0)
        value = raw_value if raw_value is not None else getattr(entity, "value", None)
        known_type = self.config.tier_for_type(entity_type) is not None

        has_risk = (getattr(entity, "risk_level", None) is not None
                    or getattr(entity, "risk", None) is not None)
        detector_risk = entity_risk_name(entity) if has_risk else None
        risk = self.effective_risk(entity_type, detector_risk)

        if self.is_allow_listed(value):
            return PolicyDecision(entity_id, entity_type, page, risk, "ALLOW", confidence,
                                  "allow_list_match", allow_listed=True)

        rule = self.config.tiers[risk]
        if confidence >= rule.min_confidence_to_redact:
            action, reason = rule.action, f"{risk.lower()}_confident"
        else:
            action = rule.uncertainty_action
            reason = (f"{risk.lower()}_below_confidence"
                      f"({confidence:.2f}<{rule.min_confidence_to_redact:.2f})")

        if not known_type:
            # Unknown types never get a weaker action than the unknown-entity policy.
            if self.config.unknown_action == "BLOCK" or action == "BLOCK":
                action = "BLOCK"
            elif action == "ALLOW":
                action = self.config.unknown_action
            reason = f"unknown_entity_type;{reason}"

        return PolicyDecision(entity_id, entity_type, page, risk, action, confidence, reason)

    def apply(
        self,
        entities: Iterable[Any],
        raw_values: Optional[Mapping[str, str]] = None,
        mutate: bool = True,
    ) -> PolicyResult:
        """
        Evaluate every entity and (by default) write action/risk back onto it.

        Args:
            entities:   PIIEntity (Person 3) or EntityAnnotation (Person 1) objects.
            raw_values: Optional {entity_id: raw text} for entity types that carry
                        no raw value (EntityAnnotation). Used only for allow-listing.
            mutate:     Set entity.action / risk from the decision.
        """
        raw_values = raw_values or {}
        entities = list(entities)
        result = PolicyResult(policy_version=self.config.version)

        for entity in entities:
            entity_id = str(getattr(entity, "entity_id", ""))
            decision = self.evaluate_entity(entity, raw_values.get(entity_id))
            result.decisions.append(decision)
            if mutate:
                _set_entity_fields(entity, decision.action, decision.risk, decision)
            if decision.action == "BLOCK":
                result.block_reasons.append(
                    f"{decision.entity_type} on page {decision.page}: {decision.reason}"
                )

        actions = {d.action for d in result.decisions}
        if "BLOCK" in actions:
            result.document_action = "BLOCK"
        elif actions - {"ALLOW"}:
            result.document_action = "REDACT"
        else:
            result.document_action = "ALLOW"

        result.inherent_risk = max_risk(
            d.risk for d in result.decisions if d.action != "ALLOW"
        )
        return result

    def apply_to_document(self, document: Any) -> PolicyResult:
        """Apply the policy to CanonicalDocument.entities in place."""
        result = self.apply(getattr(document, "entities", []) or [])
        metadata = getattr(document, "metadata", None)
        if isinstance(metadata, dict):
            metadata["policy_summary"] = {
                "document_action": result.document_action,
                "inherent_risk": result.inherent_risk,
                "action_counts": result.action_counts,
            }
        return result
