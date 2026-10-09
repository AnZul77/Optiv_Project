"""
Schema Package
==============

Canonical document representation, structural extraction schemas,
PII detection taxonomy, enums, risk specifications, and entity annotations.
"""

from src.schema.document import (
    CanonicalDocument,
    ExtractedPage,
    ExtractedBlock,
    ExtractedImage,
    ExtractedTable,
    TableCell,
    BoundingBox,
    EntityAnnotation,
    ExtractionResult,
    PipelineMetadata,
)
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
    # Document representations (Person 1)
    "CanonicalDocument",
    "ExtractedPage",
    "ExtractedBlock",
    "ExtractedImage",
    "ExtractedTable",
    "TableCell",
    "BoundingBox",
    "EntityAnnotation",
    "ExtractionResult",
    "PipelineMetadata",
    # PII Detection & Context representations (Person 3)
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
