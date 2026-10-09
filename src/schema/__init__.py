"""
Schema Package
==============

Canonical data models, enums, and risk specifications for the PII Security Firewall.
"""

from src.schema.entities import (
    EntityType,
    RiskLevel,
    Action,
    DetectionSource,
    ValidatorStatus,
    RISK_MAPPING,
    TableContext,
    ContentBlock,
    PIIEntity,
    DetectionMetadata,
    DetectionResult,
    ConfidenceWeights,
    DEFAULT_CONFIDENCE_WEIGHTS,
    compute_value_hash,
)

__all__ = [
    "EntityType",
    "RiskLevel",
    "Action",
    "DetectionSource",
    "ValidatorStatus",
    "RISK_MAPPING",
    "TableContext",
    "ContentBlock",
    "PIIEntity",
    "DetectionMetadata",
    "DetectionResult",
    "ConfidenceWeights",
    "DEFAULT_CONFIDENCE_WEIGHTS",
    "compute_value_hash",
]
