"""
Canonical PII Entity Data Models
================================

This module defines the shared data contracts for the entire PII Security Firewall
pipeline. All detection layers produce `PIIEntity` instances, and the pipeline
outputs a unified `DetectionResult`.

**Ownership:** Person 3 (PII Detection & Context Engine Lead)
**Consumers:** Person 4 (Policy Engine), Person 5 (Evaluation & UI)
**Status:** FROZEN after Day 5 checkpoint — changes require all-team approval.

Schema Design Principles:
    - Every detected entity gets a UUID for traceability
    - Raw PII values are stored transiently in-memory only; `value_hash` is 
      the persistent identifier used in audit logs
    - Confidence is a composite 0.0–1.0 score aggregated across detection layers
    - Risk level is derived from entity type via RISK_MAPPING
    - Bounding box coordinates enable pixel-level image redaction (Person 2)
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# =============================================================================
# Enumerations
# =============================================================================

class EntityType(str, Enum):
    """
    Comprehensive PII entity taxonomy.

    Organized by category:
        - Identity:      PERSON, DOB, ADDRESS
        - Contact:       EMAIL, PHONE
        - Organization:  EMPLOYEE_ID, DIRECTOR_ID
        - National IDs:  SSN, PASSPORT, PAN, AADHAAR, TAX_ID, NINO
        - Financial:     CARD, BANK_ACCOUNT, IFSC, GST, UPI
        - Visual:        SIGNATURE, FACE_PHOTO, SENSITIVE_SCREENSHOT
    """

    # Identity
    PERSON = "PERSON"
    DOB = "DOB"
    ADDRESS = "ADDRESS"

    # Contact
    EMAIL = "EMAIL"
    PHONE = "PHONE"

    # Organization IDs
    EMPLOYEE_ID = "EMPLOYEE_ID"
    DIRECTOR_ID = "DIRECTOR_ID"

    # National / Government IDs
    SSN = "SSN"
    PASSPORT = "PASSPORT"
    PAN = "PAN"
    AADHAAR = "AADHAAR"
    TAX_ID = "TAX_ID"
    NINO = "NINO"

    # Financial
    CARD = "CARD"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    IFSC = "IFSC"
    GST = "GST"
    UPI = "UPI"

    # Visual Signals (detected by Person 2, consumed here)
    SIGNATURE = "SIGNATURE"
    FACE_PHOTO = "FACE_PHOTO"
    SENSITIVE_SCREENSHOT = "SENSITIVE_SCREENSHOT"


class RiskLevel(str, Enum):
    """
    Risk classification for PII entities.

    Determines the default policy action:
        - CRITICAL: Always REDACT or BLOCK (SSN, Passport, PAN, Aadhaar, Cards, NINO)
        - HIGH:     REDACT by default (Email, Phone, Name, Address, DOB, Employee ID)
        - MEDIUM:   REDACT with possible ALLOW override (IFSC, GST, UPI)
        - LOW:      Context-dependent (generic data that may or may not be PII)
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Action(str, Enum):
    """
    Action to take on a detected PII entity.

    Assigned by the Policy Engine (Person 4) based on risk level and policy config.
        - REDACT:  Replace with [REDACTED_TYPE] and burn pixels
        - BLOCK:   Halt entire document processing (entity too dangerous to redact)
        - ALLOW:   Pass through (business code / allow-listed reference)
        - REVIEW:  Flag for manual review (low confidence or ambiguous)
    """

    REDACT = "REDACT"
    BLOCK = "BLOCK"
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"


class DetectionSource(str, Enum):
    """Source detection layer that first identified the entity."""

    REGEX = "regex"
    NER = "ner"
    CONTEXT = "context"
    VALIDATOR = "validator"
    RESOLVED = "resolved"
    VISUAL = "visual"


class ValidatorStatus(str, Enum):
    """Result of algorithmic validation on an entity."""

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# =============================================================================
# Risk Mapping
# =============================================================================

RISK_MAPPING: Dict[EntityType, RiskLevel] = {
    # CRITICAL — Government-issued IDs and financial instruments
    EntityType.SSN: RiskLevel.CRITICAL,
    EntityType.PASSPORT: RiskLevel.CRITICAL,
    EntityType.PAN: RiskLevel.CRITICAL,
    EntityType.AADHAAR: RiskLevel.CRITICAL,
    EntityType.CARD: RiskLevel.CRITICAL,
    EntityType.NINO: RiskLevel.CRITICAL,

    # HIGH — Personal identifiers and contact information
    EntityType.PERSON: RiskLevel.HIGH,
    EntityType.EMAIL: RiskLevel.HIGH,
    EntityType.PHONE: RiskLevel.HIGH,
    EntityType.DOB: RiskLevel.HIGH,
    EntityType.ADDRESS: RiskLevel.HIGH,
    EntityType.EMPLOYEE_ID: RiskLevel.HIGH,
    EntityType.DIRECTOR_ID: RiskLevel.HIGH,
    EntityType.BANK_ACCOUNT: RiskLevel.HIGH,
    EntityType.TAX_ID: RiskLevel.HIGH,

    # MEDIUM — Institutional identifiers
    EntityType.IFSC: RiskLevel.MEDIUM,
    EntityType.GST: RiskLevel.MEDIUM,
    EntityType.UPI: RiskLevel.MEDIUM,

    # HIGH — Visual signals (could contain any PII)
    EntityType.SIGNATURE: RiskLevel.HIGH,
    EntityType.FACE_PHOTO: RiskLevel.HIGH,
    EntityType.SENSITIVE_SCREENSHOT: RiskLevel.HIGH,
}

# Default risk for unknown entity types (fail-closed philosophy)
DEFAULT_RISK_LEVEL = RiskLevel.HIGH


# =============================================================================
# Salt for Hashing (configurable per deployment)
# =============================================================================

# In production, this should be loaded from environment or secrets manager
_HASH_SALT: str = "pii-firewall-default-salt-change-in-production"


def set_hash_salt(salt: str) -> None:
    """Set the global hash salt for PII value hashing."""
    global _HASH_SALT
    _HASH_SALT = salt


def compute_value_hash(value: str) -> str:
    """
    Compute a salted SHA-256 hash of a PII value.

    This hash is used in audit logs and entity deduplication
    so that raw PII values are never persisted.

    Args:
        value: The raw PII text value.

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    salted = f"{_HASH_SALT}:{value}"
    return hashlib.sha256(salted.encode("utf-8")).hexdigest()


# =============================================================================
# Core Data Models
# =============================================================================

@dataclass
class TableContext:
    """
    Table-level context for a content block that originated from a table cell.

    Used by the Context Engine (Layer 3) to propagate column headers
    as entity type hints to cell values.

    Example:
        If column_headers = ["Employee ID", "Name", "Email", "SSN"],
        then cell values in column 3 inherit type SSN even without regex context.
    """

    column_headers: List[str] = field(default_factory=list)
    header_name: str = ""
    row_index: int = 0
    col_index: int = 0
    table_id: str = ""

    def __post_init__(self):
        if self.header_name and not self.column_headers:
            self.column_headers = [self.header_name]


@dataclass
class ContentBlock:
    """
    A unified text block extracted from any document format.

    This is the input contract from Person 1 (Ingestion) and Person 2 (OCR).
    Every block of text — whether from native PDF text, OCR output, table cells,
    metadata fields, or speaker notes — is represented as a ContentBlock.

    Attributes:
        block_id:        Unique identifier for this block.
        source_type:     Origin: "native_text", "ocr_text", "table", "metadata", "notes".
        text:            The extracted text content.
        page:            Page or slide number (1-indexed).
        bbox:            Bounding box in pixels (x1, y1, x2, y2). None for native text.
        ocr_confidence:  OCR engine confidence (0.0–1.0). None for native text.
        table_context:   Column headers and position for table-sourced blocks.
        section_context: Enclosing section heading or title, if available.
        source_file:     Original filename of the uploaded document.
    """

    block_id: str = ""
    source_type: str = "native_text"
    text: str = ""
    page: int = 0
    bbox: Optional[Tuple[int, int, int, int]] = None
    ocr_confidence: Optional[float] = None
    table_context: Optional[TableContext] = None
    section_context: Optional[str] = None
    source_file: str = ""


@dataclass
class PIIEntity:
    """
    A single detected PII entity with full provenance.

    This is the canonical output of the detection pipeline. Each entity
    carries its type, confidence, risk level, source coordinates, and
    the detection layers that contributed to its identification.

    Lifecycle:
        1. Created by a detection layer (regex, NER, context)
        2. Validated by the ValidatorEngine (confidence adjusted)
        3. Merged by the EntityResolver (overlaps resolved)
        4. Consumed by the Policy Engine (action assigned)
        5. Used by the Redactor (text/image replacement)
        6. Logged by the Audit Logger (hash-only, zero raw PII)

    Attributes:
        entity_id:        UUID v4 (urn:uuid:...) for unique tracking.
        entity_type:      PII category from EntityType enum.
        value:            Raw detected text (NEVER logged or persisted).
        value_hash:       Salted SHA-256 hash for audit and dedup.
        source:           Primary detection layer that first found this entity.
        detection_layers: All layers that confirmed this entity.
        confidence:       Composite score (0.0–1.0) from all contributing layers.
        risk_level:       Derived from RISK_MAPPING[entity_type].
        action:           Policy action (set by P4's Policy Engine, default REDACT).
        page:             Page/slide number (1-indexed).
        bbox:             Pixel bounding box for image redaction.
        text_start:       Character offset (start) within the ContentBlock text.
        text_end:         Character offset (end) within the ContentBlock text.
        block_id:         Reference to the source ContentBlock.
        context_cues:     Cue words that influenced detection (e.g., ["SSN:"]).
        validator_result: Algorithmic validation status.
    """

    entity_id: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    entity_type: EntityType = EntityType.PERSON
    value: str = ""
    value_hash: str = ""
    source: DetectionSource = DetectionSource.REGEX
    detection_layers: List[str] = field(default_factory=list)
    confidence: float = 0.0
    risk_level: RiskLevel = RiskLevel.HIGH
    action: Action = Action.REDACT
    page: int = 0
    bbox: Optional[Tuple[int, int, int, int]] = None
    text_start: int = 0
    text_end: int = 0
    block_id: str = ""
    context_cues: List[str] = field(default_factory=list)
    validator_result: ValidatorStatus = ValidatorStatus.NOT_APPLICABLE

    def __post_init__(self):
        """Auto-compute derived fields after initialization."""
        # Auto-compute hash if value is provided but hash is empty
        if self.value and not self.value_hash:
            self.value_hash = compute_value_hash(self.value)

        # Auto-assign risk level from entity type if using default
        if self.entity_type in RISK_MAPPING:
            self.risk_level = RISK_MAPPING[self.entity_type]
        else:
            self.risk_level = DEFAULT_RISK_LEVEL

        # Coerce source to DetectionSource if given as string
        if isinstance(self.source, str):
            try:
                self.source = DetectionSource(self.source)
            except ValueError:
                pass

        # Ensure detection_layers includes the source
        src_val = self.source.value if isinstance(self.source, DetectionSource) else str(self.source)
        if src_val not in self.detection_layers:
            self.detection_layers.append(src_val)

    def to_audit_dict(self) -> Dict:
        """
        Export entity as an audit-safe dictionary.

        The raw `value` field is EXCLUDED — only the hash is included.
        This dict is safe for logging and persistence.
        """
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.value,
            "value_hash": self.value_hash,
            "source": self.source.value,
            "detection_layers": self.detection_layers,
            "confidence": round(self.confidence, 4),
            "risk_level": self.risk_level.value,
            "action": self.action.value,
            "page": self.page,
            "bbox": list(self.bbox) if self.bbox else None,
            "text_start": self.text_start,
            "text_end": self.text_end,
            "block_id": self.block_id,
            "context_cues": self.context_cues,
            "validator_result": self.validator_result.value,
        }

    def to_display_dict(self) -> Dict:
        """
        Export entity for UI display (Streamlit dashboard).

        Includes a masked preview of the value for operator review,
        but never the full raw value.
        """
        masked = self._mask_value(self.value) if self.value else "***"
        return {
            "entity_id": self.entity_id,
            "type": self.entity_type.value,
            "masked_value": masked,
            "confidence": f"{self.confidence:.1%}",
            "risk": self.risk_level.value,
            "action": self.action.value,
            "page": self.page,
            "layers": ", ".join(self.detection_layers),
            "cues": ", ".join(self.context_cues) if self.context_cues else "—",
        }

    @staticmethod
    def _mask_value(value: str) -> str:
        """
        Mask a PII value for display, showing only first/last characters.

        Examples:
            "123-45-6789" → "1••-••-••89"
            "john@mail.com" → "j•••@••••.com"
            "Rahul Sharma" → "R•••l S•••a"
        """
        if len(value) <= 2:
            return "••"
        if len(value) <= 4:
            return value[0] + "••" + value[-1]
        return value[0] + "•" * (len(value) - 2) + value[-1]

    def merge_with(self, other: PIIEntity) -> PIIEntity:
        """
        Merge another overlapping entity into this one.

        Keeps the higher confidence, combines detection layers and context cues.
        Used by the EntityResolver.
        """
        merged = PIIEntity(
            entity_id=self.entity_id,
            entity_type=self.entity_type if self.confidence >= other.confidence else other.entity_type,
            value=self.value if self.confidence >= other.confidence else other.value,
            source=self.source if self.confidence >= other.confidence else other.source,
            detection_layers=list(set(self.detection_layers + other.detection_layers)),
            confidence=max(self.confidence, other.confidence),
            risk_level=self.risk_level if self.risk_level.value <= other.risk_level.value else other.risk_level,
            action=self.action,
            page=self.page,
            bbox=self.bbox or other.bbox,
            text_start=min(self.text_start, other.text_start),
            text_end=max(self.text_end, other.text_end),
            block_id=self.block_id,
            context_cues=list(set(self.context_cues + other.context_cues)),
            validator_result=(
                self.validator_result
                if self.validator_result != ValidatorStatus.NOT_APPLICABLE
                else other.validator_result
            ),
        )
        return merged


@dataclass
class DetectionMetadata:
    """
    Aggregate metadata about a detection pipeline run.

    Used for monitoring, debugging, and evaluation reporting.
    """

    regex_matches: int = 0
    ner_matches: int = 0
    context_matches: int = 0
    validator_adjustments: int = 0
    resolved_merges: int = 0
    allow_list_rejections: int = 0
    processing_time_ms: float = 0.0
    blocks_processed: int = 0
    pages_processed: int = 0


@dataclass
class DetectionResult:
    """
    Complete output of the detection pipeline for a single document.

    This is the primary interface contract with Person 4 (Policy Engine).
    Contains all detected entities, summary statistics, and processing metadata.

    Attributes:
        document_id:        Unique identifier for the processed document.
        source_file:        Original filename.
        total_entities:     Count of resolved entities.
        entities:           List of all detected PIIEntity instances.
        entity_type_counts: Breakdown by entity type (e.g., {"SSN": 3, "EMAIL": 12}).
        risk_summary:       Breakdown by risk level (e.g., {"CRITICAL": 5, "HIGH": 8}).
        detection_metadata: Processing statistics from each detection layer.
        is_blocked:         True if any entity triggered BLOCK action.
        block_reasons:      List of reasons for blocking (empty if not blocked).
    """

    document_id: str = field(default_factory=lambda: f"doc-{uuid.uuid4().hex[:12]}")
    source_file: str = ""
    total_entities: int = 0
    entities: List[PIIEntity] = field(default_factory=list)
    entity_type_counts: Dict[str, int] = field(default_factory=dict)
    risk_summary: Dict[str, int] = field(default_factory=dict)
    detection_metadata: DetectionMetadata = field(default_factory=DetectionMetadata)
    is_blocked: bool = False
    block_reasons: List[str] = field(default_factory=list)

    def compute_summaries(self) -> None:
        """
        Recompute entity_type_counts, risk_summary, and total_entities
        from the current entities list.

        Call this after all entities have been added/resolved.
        """
        self.total_entities = len(self.entities)

        # Entity type counts
        type_counts: Dict[str, int] = {}
        for entity in self.entities:
            type_name = entity.entity_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        self.entity_type_counts = type_counts

        # Risk summary
        risk_counts: Dict[str, int] = {}
        for entity in self.entities:
            risk_name = entity.risk_level.value
            risk_counts[risk_name] = risk_counts.get(risk_name, 0) + 1
        self.risk_summary = risk_counts

        # Check for blocking entities
        blocked_entities = [e for e in self.entities if e.action == Action.BLOCK]
        self.is_blocked = len(blocked_entities) > 0
        self.block_reasons = [
            f"{e.entity_type.value} detected on page {e.page} (confidence: {e.confidence:.2f})"
            for e in blocked_entities
        ]

    def get_entities_by_type(self, entity_type: EntityType) -> List[PIIEntity]:
        """Filter entities by type."""
        return [e for e in self.entities if e.entity_type == entity_type]

    def get_entities_by_risk(self, risk_level: RiskLevel) -> List[PIIEntity]:
        """Filter entities by risk level."""
        return [e for e in self.entities if e.risk_level == risk_level]

    def get_entities_by_page(self, page: int) -> List[PIIEntity]:
        """Filter entities by page number."""
        return [e for e in self.entities if e.page == page]

    def get_critical_entities(self) -> List[PIIEntity]:
        """Get all CRITICAL risk entities (SSN, Passport, PAN, Aadhaar, Card, NINO)."""
        return self.get_entities_by_risk(RiskLevel.CRITICAL)

    def has_unresolved_critical(self) -> bool:
        """
        Check if there are any CRITICAL entities with low confidence.

        Used by the fail-closed gate — if True, the document should be BLOCKED
        because we're uncertain about critical PII.
        """
        for entity in self.get_critical_entities():
            if entity.confidence < 0.80 and entity.action != Action.ALLOW:
                return True
        return False


# =============================================================================
# Confidence Weights Configuration
# =============================================================================

@dataclass
class ConfidenceWeights:
    """
    Tunable weights for composite confidence score aggregation.

    The composite confidence is computed as:
        confidence = w_regex * S_regex + w_ner * S_ner + w_context * S_context
                   + w_validator * S_validator + w_structure * S_structure

    These weights are tuned on Day 15 using dev set performance.
    """

    w_regex: float = 0.30
    w_ner: float = 0.25
    w_context: float = 0.20
    w_validator: float = 0.15
    w_structure: float = 0.10

    def __post_init__(self):
        """Validate that weights sum to approximately 1.0."""
        total = self.w_regex + self.w_ner + self.w_context + self.w_validator + self.w_structure
        if abs(total - 1.0) > 0.01:
            raise ValueError(
                f"Confidence weights must sum to 1.0 (got {total:.3f}). "
                f"Weights: regex={self.w_regex}, ner={self.w_ner}, "
                f"context={self.w_context}, validator={self.w_validator}, "
                f"structure={self.w_structure}"
            )

    def compute(
        self,
        regex_score: float = 0.0,
        ner_score: float = 0.0,
        context_score: float = 0.0,
        validator_score: float = 0.0,
        structure_score: float = 0.0,
    ) -> float:
        """
        Compute composite confidence from individual layer scores.

        Each input score should be in [0.0, 1.0].
        Returns a clamped [0.0, 1.0] composite confidence.
        """
        raw = (
            self.w_regex * regex_score
            + self.w_ner * ner_score
            + self.w_context * context_score
            + self.w_validator * validator_score
            + self.w_structure * structure_score
        )
        return max(0.0, min(1.0, raw))


# =============================================================================
# Default Confidence Weights Instance & Aliases
# =============================================================================

DEFAULT_CONFIDENCE_WEIGHTS = ConfidenceWeights()

# Type alias for external interoperability
EntityAnnotation = PIIEntity

