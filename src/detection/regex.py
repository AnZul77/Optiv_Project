"""
Regex Detection Engine (Layer 1)
================================

High-precision deterministic pattern matching for structured PII.

This is the first detection layer in the pipeline. It uses compiled regular
expressions to detect PII entities with known formats: SSN, Email, Phone,
PAN, Aadhaar, Passport, Credit Cards, Employee IDs, and financial codes.

Design Principles:
    - Patterns are organized by entity type, ordered by specificity
    - Allow-list filtering runs BEFORE pattern matching to reject false positives early
    - Character offsets are tracked precisely via match.start() / match.end()
    - Base confidence is set per-pattern (more specific = higher confidence)
    - Bare digit sequences (e.g., 9-digit numbers) are only flagged WITH context cues

**Ownership:** Person 3 (PII Detection & Context Engine Lead)
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from src.schema.entities import (
    PIIEntity,
    EntityType,
    DetectionSource,
    ContentBlock,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Pattern Definition
# =============================================================================

@dataclass
class PIIPattern:
    """
    A single regex pattern for PII detection.

    Attributes:
        entity_type:     The PII type this pattern detects.
        pattern:         Compiled regex pattern.
        base_confidence: Confidence score assigned when this pattern matches.
        description:     Human-readable description of what the pattern matches.
        requires_context: If True, pattern only fires when a context cue is nearby.
    """

    entity_type: EntityType
    pattern: re.Pattern
    base_confidence: float
    description: str = ""
    requires_context: bool = False


# =============================================================================
# Allow-List Patterns (Business Codes — False Positive Prevention)
# =============================================================================

ALLOW_LIST_PATTERNS: List[re.Pattern] = [
    re.compile(r"\bINC-\d{4}-\d+\b"),          # Incident reference (e.g., INC-2026-0417)
    re.compile(r"\bRSK-\d+\b"),                # Risk reference (e.g., RSK-001)
    re.compile(r"\bGRP-POL-\d+\b"),            # Group policy reference
    re.compile(r"\bCTL-IAM-\d+\b"),            # Control reference
    re.compile(r"\bREQ-\d+\b"),                # Request reference
    re.compile(r"\bAUDIT-\d+\b"),              # Audit reference
    re.compile(r"\bVEN-\d+\b"),                # Vendor reference
    re.compile(r"\bTPRM-\d+\b"),               # TPRM reference
    re.compile(r"\bPOL-\d+\b"),                # Policy reference
    re.compile(r"\bCTL-\d+\b"),                # Control ID
    re.compile(r"\bISO[-\s]?\d{4,5}\b"),       # ISO standard references
    re.compile(r"\bNIST[-\s]?\w+[-\s]?\d+\b"), # NIST framework references
]


# =============================================================================
# PII Regex Pattern Catalog
# =============================================================================

def _build_pattern_catalog() -> Dict[EntityType, List[PIIPattern]]:
    """
    Build the complete regex pattern catalog.

    Patterns are ordered by specificity within each entity type —
    more specific patterns first to avoid over-matching.

    Returns:
        Dictionary mapping EntityType → list of PIIPatterns.
    """

    catalog: Dict[EntityType, List[PIIPattern]] = {}

    # -------------------------------------------------------------------------
    # SSN (US Social Security Number)
    # -------------------------------------------------------------------------
    catalog[EntityType.SSN] = [
        PIIPattern(
            entity_type=EntityType.SSN,
            pattern=re.compile(
                r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
            ),
            base_confidence=0.92,
            description="SSN with dashes (XXX-XX-XXXX) — excludes invalid area numbers",
        ),
        PIIPattern(
            entity_type=EntityType.SSN,
            pattern=re.compile(
                r"\b(?!000|666|9\d{2})\d{3}\s(?!00)\d{2}\s(?!0000)\d{4}\b"
            ),
            base_confidence=0.88,
            description="SSN with spaces (XXX XX XXXX)",
        ),
        PIIPattern(
            entity_type=EntityType.SSN,
            pattern=re.compile(
                r"\b(?!000|666|9\d{2})\d{9}\b"
            ),
            base_confidence=0.50,
            description="SSN without separators (9 digits) — LOW confidence, needs context",
            requires_context=True,
        ),
    ]

    # -------------------------------------------------------------------------
    # EMAIL
    # -------------------------------------------------------------------------
    catalog[EntityType.EMAIL] = [
        PIIPattern(
            entity_type=EntityType.EMAIL,
            pattern=re.compile(
                r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
            ),
            base_confidence=0.95,
            description="Standard email address (user@domain.tld)",
        ),
    ]

    # -------------------------------------------------------------------------
    # PHONE (Multi-country)
    # -------------------------------------------------------------------------
    catalog[EntityType.PHONE] = [
        # International with country code
        PIIPattern(
            entity_type=EntityType.PHONE,
            pattern=re.compile(
                r"\+\d{1,3}[\s\-.]?\(?\d{1,4}\)?[\s\-.]?\d{2,4}[\s\-.]?\d{2,4}[\s\-.]?\d{0,4}"
            ),
            base_confidence=0.90,
            description="International phone with country code (+XX ...)",
        ),
        # US format: (XXX) XXX-XXXX or XXX-XXX-XXXX
        PIIPattern(
            entity_type=EntityType.PHONE,
            pattern=re.compile(
                r"\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b"
            ),
            base_confidence=0.80,
            description="US phone: (XXX) XXX-XXXX or XXX-XXX-XXXX",
        ),
        # India: +91 or 0 prefix with 10 digits
        PIIPattern(
            entity_type=EntityType.PHONE,
            pattern=re.compile(
                r"(?:\+91[\s\-]?|0)?[6-9]\d{4}[\s\-]?\d{5}\b"
            ),
            base_confidence=0.82,
            description="Indian mobile: +91-XXXXX-XXXXX or 0XXXXXXXXXX",
        ),
    ]

    # -------------------------------------------------------------------------
    # PAN (Indian Permanent Account Number)
    # -------------------------------------------------------------------------
    catalog[EntityType.PAN] = [
        PIIPattern(
            entity_type=EntityType.PAN,
            pattern=re.compile(
                r"\b[A-Z]{3}[PCHATBLJFG][A-Z]\d{4}[A-Z]\b"
            ),
            base_confidence=0.90,
            description="Indian PAN: XXXPX1234X (4th char = entity type P/C/H/A/T/B/L/J/F/G)",
        ),
        PIIPattern(
            entity_type=EntityType.PAN,
            pattern=re.compile(
                r"\b[A-Z]{5}\d{4}[A-Z]\b"
            ),
            base_confidence=0.75,
            description="Indian PAN (relaxed — any 5 alpha + 4 digits + 1 alpha)",
            requires_context=True,
        ),
    ]

    # -------------------------------------------------------------------------
    # AADHAAR (Indian Unique ID — 12 digits)
    # -------------------------------------------------------------------------
    catalog[EntityType.AADHAAR] = [
        PIIPattern(
            entity_type=EntityType.AADHAAR,
            pattern=re.compile(
                r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b"
            ),
            base_confidence=0.88,
            description="Aadhaar with spaces: XXXX XXXX XXXX (starts with 2-9)",
        ),
        PIIPattern(
            entity_type=EntityType.AADHAAR,
            pattern=re.compile(
                r"\b[2-9]\d{3}-\d{4}-\d{4}\b"
            ),
            base_confidence=0.88,
            description="Aadhaar with dashes: XXXX-XXXX-XXXX",
        ),
        PIIPattern(
            entity_type=EntityType.AADHAAR,
            pattern=re.compile(
                r"\b[2-9]\d{11}\b"
            ),
            base_confidence=0.50,
            description="Aadhaar without separators (12 digits starting 2-9) — needs context",
            requires_context=True,
        ),
    ]

    # -------------------------------------------------------------------------
    # PASSPORT
    # -------------------------------------------------------------------------
    catalog[EntityType.PASSPORT] = [
        # Indian passport: 1 letter + 7 digits
        PIIPattern(
            entity_type=EntityType.PASSPORT,
            pattern=re.compile(
                r"\b[A-Z][0-9]{7}\b"
            ),
            base_confidence=0.70,
            description="Indian passport: X1234567 (letter + 7 digits)",
            requires_context=True,
        ),
        # US passport: 9 digits (context-dependent)
        PIIPattern(
            entity_type=EntityType.PASSPORT,
            pattern=re.compile(
                r"\b\d{9}\b"
            ),
            base_confidence=0.40,
            description="US passport: 9 digits (very low confidence without context)",
            requires_context=True,
        ),
    ]

    # -------------------------------------------------------------------------
    # CARD (Credit / Debit Cards)
    # -------------------------------------------------------------------------
    catalog[EntityType.CARD] = [
        # 16 digits with separators
        PIIPattern(
            entity_type=EntityType.CARD,
            pattern=re.compile(
                r"\b(?:4\d{3}|5[1-5]\d{2}|6011|622[1-9]|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
            ),
            base_confidence=0.92,
            description="Card number with known prefix (Visa/MC/Amex/Discover)",
        ),
        PIIPattern(
            entity_type=EntityType.CARD,
            pattern=re.compile(
                r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b"
            ),
            base_confidence=0.80,
            description="Generic 16-digit card with separators",
        ),
    ]

    # -------------------------------------------------------------------------
    # EMPLOYEE_ID
    # -------------------------------------------------------------------------
    catalog[EntityType.EMPLOYEE_ID] = [
        PIIPattern(
            entity_type=EntityType.EMPLOYEE_ID,
            pattern=re.compile(
                r"\bEMP[-\s]?\d{4,8}\b", re.IGNORECASE
            ),
            base_confidence=0.90,
            description="Employee ID: EMP-XXXX to EMP-XXXXXXXX",
        ),
        PIIPattern(
            entity_type=EntityType.EMPLOYEE_ID,
            pattern=re.compile(
                r"\bE\d{5,7}\b"
            ),
            base_confidence=0.65,
            description="Employee ID: EXXXXX (E + 5-7 digits)",
            requires_context=True,
        ),
    ]

    # -------------------------------------------------------------------------
    # DIRECTOR_ID (Indian DIN)
    # -------------------------------------------------------------------------
    catalog[EntityType.DIRECTOR_ID] = [
        PIIPattern(
            entity_type=EntityType.DIRECTOR_ID,
            pattern=re.compile(
                r"\bDIN[-\s]?\d{8}\b", re.IGNORECASE
            ),
            base_confidence=0.90,
            description="Director Identification Number: DIN-XXXXXXXX",
        ),
    ]

    # -------------------------------------------------------------------------
    # DOB (Date of Birth)
    # -------------------------------------------------------------------------
    catalog[EntityType.DOB] = [
        # MM/DD/YYYY or DD/MM/YYYY
        PIIPattern(
            entity_type=EntityType.DOB,
            pattern=re.compile(
                r"\b(?:0[1-9]|[12]\d|3[01])[/\-.](?:0[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b"
            ),
            base_confidence=0.65,
            description="Date: DD/MM/YYYY or DD-MM-YYYY (needs context for DOB vs generic date)",
            requires_context=True,
        ),
        # YYYY-MM-DD (ISO format)
        PIIPattern(
            entity_type=EntityType.DOB,
            pattern=re.compile(
                r"\b(?:19|20)\d{2}[/\-.](?:0[1-9]|1[0-2])[/\-.](?:0[1-9]|[12]\d|3[01])\b"
            ),
            base_confidence=0.65,
            description="Date: YYYY-MM-DD (ISO format, needs context for DOB)",
            requires_context=True,
        ),
        # Month name formats: "March 15, 1985" or "15 March 1985"
        PIIPattern(
            entity_type=EntityType.DOB,
            pattern=re.compile(
                r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+(?:19|20)\d{2}\b",
                re.IGNORECASE,
            ),
            base_confidence=0.60,
            description="Date with month name: 'March 15, 1985'",
            requires_context=True,
        ),
        PIIPattern(
            entity_type=EntityType.DOB,
            pattern=re.compile(
                r"\b\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+(?:19|20)\d{2}\b",
                re.IGNORECASE,
            ),
            base_confidence=0.60,
            description="Date with month name: '15 March 1985'",
            requires_context=True,
        ),
    ]

    # -------------------------------------------------------------------------
    # IFSC (Indian Financial System Code)
    # -------------------------------------------------------------------------
    catalog[EntityType.IFSC] = [
        PIIPattern(
            entity_type=EntityType.IFSC,
            pattern=re.compile(
                r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
            ),
            base_confidence=0.85,
            description="IFSC Code: XXXX0XXXXXX (5th character is always 0)",
        ),
    ]

    # -------------------------------------------------------------------------
    # GST (Indian Goods and Services Tax ID)
    # -------------------------------------------------------------------------
    catalog[EntityType.GST] = [
        PIIPattern(
            entity_type=EntityType.GST,
            pattern=re.compile(
                r"\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[Z][A-Z0-9]\b"
            ),
            base_confidence=0.92,
            description="GSTIN: State(2) + PAN(10) + Entity(1) + Z + Check(1)",
        ),
    ]

    # -------------------------------------------------------------------------
    # UPI (Unified Payments Interface — India)
    # -------------------------------------------------------------------------
    catalog[EntityType.UPI] = [
        PIIPattern(
            entity_type=EntityType.UPI,
            pattern=re.compile(
                r"\b[\w.]+@(?:upi|paytm|ybl|oksbi|okaxis|okhdfcbank|okicici|apl|ibl)\b",
                re.IGNORECASE,
            ),
            base_confidence=0.90,
            description="UPI VPA: user@provider (known UPI providers only)",
        ),
    ]

    # -------------------------------------------------------------------------
    # BANK_ACCOUNT (generic, context-dependent)
    # -------------------------------------------------------------------------
    catalog[EntityType.BANK_ACCOUNT] = [
        PIIPattern(
            entity_type=EntityType.BANK_ACCOUNT,
            pattern=re.compile(
                r"\b\d{9,18}\b"
            ),
            base_confidence=0.30,
            description="Bank account: 9-18 digits (very low confidence, requires context)",
            requires_context=True,
        ),
    ]

    # -------------------------------------------------------------------------
    # NINO (UK National Insurance Number)
    # -------------------------------------------------------------------------
    catalog[EntityType.NINO] = [
        PIIPattern(
            entity_type=EntityType.NINO,
            pattern=re.compile(
                r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b"
            ),
            base_confidence=0.88,
            description="UK NINO: XX 99 99 99 X (with prefix exclusions)",
        ),
    ]

    # -------------------------------------------------------------------------
    # TAX_ID (Generic — context-dependent)
    # -------------------------------------------------------------------------
    catalog[EntityType.TAX_ID] = [
        PIIPattern(
            entity_type=EntityType.TAX_ID,
            pattern=re.compile(
                r"\b\d{2}-\d{7}\b"
            ),
            base_confidence=0.60,
            description="US EIN format: XX-XXXXXXX",
            requires_context=True,
        ),
    ]

    return catalog


# =============================================================================
# Regex Engine
# =============================================================================

class RegexEngine:
    """
    Layer 1: High-precision deterministic PII pattern detector.

    Runs compiled regex patterns against text blocks and produces
    PIIEntity instances with character offsets and base confidence scores.

    Features:
        - Allow-list filtering before detection (false positive prevention)
        - Multi-variant patterns per entity type (ordered by specificity)
        - Context-dependent patterns only fire near cue words
        - Precise character offset tracking for downstream redaction
    """

    def __init__(self, custom_allow_list: Optional[List[str]] = None):
        """
        Initialize the Regex Engine.

        Args:
            custom_allow_list: Additional allow-list patterns beyond the defaults.
        """
        self.pattern_catalog = _build_pattern_catalog()
        self.allow_list = list(ALLOW_LIST_PATTERNS)

        # Add any custom allow-list patterns
        if custom_allow_list:
            for pattern_str in custom_allow_list:
                self.allow_list.append(re.compile(pattern_str))

        logger.info(
            "RegexEngine initialized: %d entity types, %d total patterns, %d allow-list rules",
            len(self.pattern_catalog),
            sum(len(patterns) for patterns in self.pattern_catalog.values()),
            len(self.allow_list),
        )

    def detect(self, block: ContentBlock) -> List[PIIEntity]:
        """
        Run all regex patterns against a content block.

        Args:
            block: The ContentBlock containing text to scan.

        Returns:
            List of PIIEntity instances found by regex matching.
        """
        if not block.text or not block.text.strip():
            return []

        text = block.text
        entities: List[PIIEntity] = []

        # Pre-compute allow-listed spans to exclude from detection
        allow_listed_spans = self._find_allow_listed_spans(text)

        # Run each entity type's patterns
        for entity_type, patterns in self.pattern_catalog.items():
            for pii_pattern in patterns:
                matches = pii_pattern.pattern.finditer(text)
                for match in matches:
                    # Skip if this match overlaps with an allow-listed span
                    if self._overlaps_allow_list(match.start(), match.end(), allow_listed_spans):
                        logger.debug(
                            "Allow-listed: '%s' at [%d:%d]",
                            match.group(), match.start(), match.end(),
                        )
                        continue

                    # Skip context-required patterns if no context cue is nearby
                    if pii_pattern.requires_context:
                        if not self._has_nearby_context(text, match.start(), entity_type):
                            continue

                    entity = PIIEntity(
                        entity_type=entity_type,
                        value=match.group(),
                        source=DetectionSource.REGEX,
                        detection_layers=["regex"],
                        confidence=pii_pattern.base_confidence,
                        page=block.page,
                        bbox=block.bbox,
                        text_start=match.start(),
                        text_end=match.end(),
                        block_id=block.block_id,
                    )

                    entities.append(entity)

        logger.info(
            "RegexEngine detected %d entities in block '%s' (page %d)",
            len(entities), block.block_id, block.page,
        )

        return entities

    def detect_batch(self, blocks: List[ContentBlock]) -> List[PIIEntity]:
        """
        Run regex detection across multiple content blocks.

        Args:
            blocks: List of ContentBlocks to scan.

        Returns:
            Combined list of all PIIEntity instances found.
        """
        all_entities: List[PIIEntity] = []
        for block in blocks:
            all_entities.extend(self.detect(block))
        return all_entities

    def _find_allow_listed_spans(self, text: str) -> List[Tuple[int, int]]:
        """Find all text spans that match allow-list patterns."""
        spans: List[Tuple[int, int]] = []
        for pattern in self.allow_list:
            for match in pattern.finditer(text):
                spans.append((match.start(), match.end()))
        return spans

    def _overlaps_allow_list(
        self, start: int, end: int, allow_spans: List[Tuple[int, int]]
    ) -> bool:
        """Check if a match span overlaps with any allow-listed span."""
        for allow_start, allow_end in allow_spans:
            if start < allow_end and end > allow_start:
                return True
        return False

    def _has_nearby_context(
        self, text: str, match_start: int, entity_type: EntityType, window: int = 80
    ) -> bool:
        """
        Check if a context-requiring pattern has a supporting cue word nearby.

        This is a lightweight check — the full Context Engine (Layer 3) does
        deeper analysis. This check prevents context-required patterns from
        firing on completely isolated digit sequences.

        Args:
            text:         The full text.
            match_start:  Start position of the regex match.
            entity_type:  The entity type to check context for.
            window:       Characters to look behind for context cues.

        Returns:
            True if a supporting context cue is found nearby.
        """
        # Look in the window before the match
        window_start = max(0, match_start - window)
        preceding_text = text[window_start:match_start].lower()

        # Quick context cue lookup (subset — full cues are in context.py)
        quick_cues = _QUICK_CONTEXT_CUES.get(entity_type, [])
        for cue in quick_cues:
            if cue in preceding_text:
                return True

        return False

    def get_pattern_count(self) -> int:
        """Get total number of compiled patterns."""
        return sum(len(patterns) for patterns in self.pattern_catalog.values())

    def get_entity_types(self) -> List[EntityType]:
        """Get all entity types covered by regex patterns."""
        return list(self.pattern_catalog.keys())


# =============================================================================
# Quick Context Cues (Lightweight — for regex gating only)
# =============================================================================

_QUICK_CONTEXT_CUES: Dict[EntityType, List[str]] = {
    EntityType.SSN: ["ssn", "social security", "ss#", "ss no", "soc sec"],
    EntityType.AADHAAR: ["aadhaar", "aadhar", "uid", "unique id", "unique identification"],
    EntityType.PASSPORT: ["passport", "travel document", "travel doc"],
    EntityType.DOB: ["dob", "date of birth", "born", "birth date", "birth day", "d.o.b"],
    EntityType.BANK_ACCOUNT: [
        "account no", "a/c", "bank account", "account number",
        "savings", "current account", "acct",
    ],
    EntityType.TAX_ID: ["tin", "tax id", "tax identification", "ein", "employer id"],
    EntityType.EMPLOYEE_ID: ["employee", "emp id", "staff no", "employee number"],
}
