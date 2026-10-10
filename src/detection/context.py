"""
Context Detection Engine (Layer 3)
===================================

Document-level and table-level context reasoning for PII detection.

This layer does NOT detect PII independently — it enhances and discovers
entities by leveraging document structure:

1. **Sliding Window Cues:** Looks for keywords like "SSN:", "DOB:", "Email:"
   near detected or potential values to boost confidence or trigger new detections.

2. **Table Header Propagation:** Inherits entity type from column headers to
   cell values (e.g., a column headed "SSN" tags all its cells as SSN type).

3. **Section-Level Triggers:** Document sections with PII-indicative headings
   (e.g., "Employee Personal Information") boost confidence for all entities
   detected within that section.

Design Principles:
    - Context never reduces confidence — it only boosts or creates new entities
    - Table header propagation uses exact header matching AND fuzzy matching
    - Section triggers are cumulative (nested sections stack)
    - New entities created by context alone get confidence 0.40–0.60 (REVIEW range)

**Ownership:** Person 3 (PII Detection & Context Engine Lead)
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from src.schema.entities import (
    PIIEntity,
    EntityType,
    DetectionSource,
    ContentBlock,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Context Cue Definitions
# =============================================================================

# Mapping from entity type to keywords that indicate proximity to that entity
CUE_PATTERNS: Dict[EntityType, List[str]] = {
    EntityType.SSN: [
        "ssn", "social security", "ss#", "ss no", "soc sec",
        "social security number", "social security no",
    ],
    EntityType.DOB: [
        "dob", "date of birth", "born", "birth date", "birthday",
        "d.o.b", "d.o.b.", "date-of-birth",
    ],
    EntityType.PAN: [
        "pan", "permanent account", "pan card", "pan no", "pan number",
        "income tax", "it returns",
    ],
    EntityType.AADHAAR: [
        "aadhaar", "aadhar", "uid", "unique identification",
        "unique id", "aadhaar no", "aadhaar number",
    ],
    EntityType.EMAIL: [
        "email", "e-mail", "mail", "email id", "email address",
        "contact email",
    ],
    EntityType.PHONE: [
        "phone", "mobile", "tel", "telephone", "contact no",
        "cell", "landline", "ph no", "phone number", "mobile no",
    ],
    EntityType.PASSPORT: [
        "passport", "passport no", "passport number",
        "travel document", "travel doc",
    ],
    EntityType.EMPLOYEE_ID: [
        "employee id", "emp id", "staff no", "employee number",
        "emp no", "staff id", "employee code",
    ],
    EntityType.ADDRESS: [
        "address", "residence", "location", "home address",
        "residential address", "office address", "postal address",
        "mailing address", "permanent address", "current address",
    ],
    EntityType.CARD: [
        "card no", "card number", "credit card", "debit card",
        "card #", "visa", "mastercard",
    ],
    EntityType.BANK_ACCOUNT: [
        "account no", "a/c", "bank account", "account number",
        "savings account", "current account", "acct no", "acct",
    ],
    EntityType.DIRECTOR_ID: [
        "din", "director id", "director identification",
    ],
    EntityType.IFSC: [
        "ifsc", "branch code", "neft", "rtgs", "bank code",
    ],
    EntityType.GST: [
        "gst", "gstin", "goods and services tax", "gst no",
        "gst number", "tax invoice",
    ],
    EntityType.UPI: [
        "upi", "vpa", "upi id", "upi address", "pay to",
    ],
    EntityType.NINO: [
        "nino", "national insurance", "ni number", "ni no",
    ],
    EntityType.TAX_ID: [
        "tin", "tax id", "tax identification", "ein",
        "employer identification",
    ],
    EntityType.PERSON: [
        "name", "employee name", "full name", "first name",
        "last name", "applicant", "candidate", "holder name",
    ],
}

# Section headings that indicate PII-rich content
SECTION_TRIGGERS: Dict[str, float] = {
    # Heading text (lowercase) → confidence boost
    "personal information": 0.20,
    "employee personal information": 0.25,
    "employee details": 0.20,
    "personal details": 0.20,
    "contact information": 0.15,
    "contact details": 0.15,
    "identification": 0.15,
    "identity verification": 0.20,
    "know your customer": 0.20,
    "kyc": 0.20,
    "kyc details": 0.20,
    "bank details": 0.15,
    "financial information": 0.15,
    "tax information": 0.15,
    "passport details": 0.20,
    "travel document details": 0.20,
    "emergency contact": 0.15,
    "next of kin": 0.15,
    "dependent information": 0.15,
    "nominee details": 0.15,
    "director information": 0.15,
    "board of directors": 0.15,
    "key personnel": 0.15,
}

# Table header aliases — maps common header text to entity types
TABLE_HEADER_MAP: Dict[str, EntityType] = {
    # Direct matches
    "ssn": EntityType.SSN,
    "social security": EntityType.SSN,
    "social security number": EntityType.SSN,
    "email": EntityType.EMAIL,
    "email address": EntityType.EMAIL,
    "e-mail": EntityType.EMAIL,
    "phone": EntityType.PHONE,
    "phone number": EntityType.PHONE,
    "mobile": EntityType.PHONE,
    "mobile number": EntityType.PHONE,
    "telephone": EntityType.PHONE,
    "tel": EntityType.PHONE,
    "name": EntityType.PERSON,
    "employee name": EntityType.PERSON,
    "full name": EntityType.PERSON,
    "first name": EntityType.PERSON,
    "last name": EntityType.PERSON,
    "dob": EntityType.DOB,
    "date of birth": EntityType.DOB,
    "birth date": EntityType.DOB,
    "address": EntityType.ADDRESS,
    "home address": EntityType.ADDRESS,
    "residential address": EntityType.ADDRESS,
    "employee id": EntityType.EMPLOYEE_ID,
    "emp id": EntityType.EMPLOYEE_ID,
    "staff no": EntityType.EMPLOYEE_ID,
    "staff id": EntityType.EMPLOYEE_ID,
    "employee number": EntityType.EMPLOYEE_ID,
    "pan": EntityType.PAN,
    "pan number": EntityType.PAN,
    "pan no": EntityType.PAN,
    "aadhaar": EntityType.AADHAAR,
    "aadhaar no": EntityType.AADHAAR,
    "aadhaar number": EntityType.AADHAAR,
    "uid": EntityType.AADHAAR,
    "passport": EntityType.PASSPORT,
    "passport no": EntityType.PASSPORT,
    "passport number": EntityType.PASSPORT,
    "card number": EntityType.CARD,
    "credit card": EntityType.CARD,
    "debit card": EntityType.CARD,
    "account number": EntityType.BANK_ACCOUNT,
    "account no": EntityType.BANK_ACCOUNT,
    "bank account": EntityType.BANK_ACCOUNT,
    "a/c no": EntityType.BANK_ACCOUNT,
    "din": EntityType.DIRECTOR_ID,
    "director id": EntityType.DIRECTOR_ID,
    "ifsc": EntityType.IFSC,
    "ifsc code": EntityType.IFSC,
    "gst": EntityType.GST,
    "gstin": EntityType.GST,
    "gst number": EntityType.GST,
    "upi": EntityType.UPI,
    "upi id": EntityType.UPI,
    "vpa": EntityType.UPI,
    "nino": EntityType.NINO,
    "national insurance": EntityType.NINO,
    "tax id": EntityType.TAX_ID,
    "tin": EntityType.TAX_ID,
}


@dataclass
class ContextCue:
    """A detected context cue near a potential PII value."""

    cue_text: str
    entity_type: EntityType
    cue_position: int
    confidence_boost: float


class ContextEngine:
    """
    Layer 3: Document-level and table-level context reasoning.

    Enhances existing entity detections and discovers new entities
    by leveraging structural and linguistic context cues.

    Three detection strategies:
        1. Sliding window cue detection (keyword proximity)
        2. Table column header propagation
        3. Section-level confidence boosting
    """

    def __init__(self, window_size: int = 80):
        """
        Initialize the Context Engine.

        Args:
            window_size: Characters to look before/after a potential value
                         for context cues (default: 80).
        """
        self.window_size = window_size
        self.cue_patterns = CUE_PATTERNS
        self.section_triggers = SECTION_TRIGGERS
        self.table_header_map = TABLE_HEADER_MAP

        # Pre-compile cue regexes for faster matching
        self._compiled_cues: Dict[EntityType, List[re.Pattern]] = {}
        for entity_type, cues in self.cue_patterns.items():
            self._compiled_cues[entity_type] = [
                re.compile(re.escape(cue), re.IGNORECASE) for cue in cues
            ]

        logger.info(
            "ContextEngine initialized: %d entity types, %d cue patterns, "
            "%d section triggers, %d table headers",
            len(self.cue_patterns),
            sum(len(c) for c in self.cue_patterns.values()),
            len(self.section_triggers),
            len(self.table_header_map),
        )

    def detect(
        self,
        block: ContentBlock,
        existing_entities: Optional[List[PIIEntity]] = None,
    ) -> List[PIIEntity]:
        """
        Run context-based detection and enhancement on a content block.

        This method:
        1. Enhances existing entities with context cues (boosts confidence)
        2. Discovers new entities via table header propagation
        3. Discovers new entities via sliding window cue + value pattern matching

        Args:
            block:              The ContentBlock to analyze.
            existing_entities:  Entities already detected by Regex/NER layers.

        Returns:
            Combined list of enhanced existing entities + newly discovered entities.
        """
        if not block.text or not block.text.strip():
            return existing_entities or []

        enhanced_entities: List[PIIEntity] = []
        new_entities: List[PIIEntity] = []

        # 1. Enhance existing entities with context cues
        if existing_entities:
            enhanced_entities = self._enhance_existing_entities(
                block.text, existing_entities
            )
        else:
            enhanced_entities = []

        # 2. Table header propagation (for table-sourced blocks)
        if block.table_context and block.table_context.column_headers:
            table_entities = self._table_header_propagation(block)
            new_entities.extend(table_entities)

        # 3. Section-level confidence boosting
        if block.section_context:
            section_boost = self._get_section_boost(block.section_context)
            if section_boost > 0:
                for entity in enhanced_entities:
                    entity.confidence = min(1.0, entity.confidence + section_boost)
                    entity.context_cues.append(f"section:{block.section_context}")
                for entity in new_entities:
                    entity.confidence = min(1.0, entity.confidence + section_boost)
                    entity.context_cues.append(f"section:{block.section_context}")

        # 4. Sliding window cue detection for new entities
        cue_entities = self._sliding_window_detection(block)
        new_entities.extend(cue_entities)

        # Combine: enhanced existing + newly discovered
        all_entities = enhanced_entities + new_entities

        logger.info(
            "ContextEngine: %d enhanced, %d new entities in block '%s'",
            len(enhanced_entities), len(new_entities), block.block_id,
        )

        return all_entities

    def detect_batch(
        self,
        blocks: List[ContentBlock],
        existing_entities_map: Optional[Dict[str, List[PIIEntity]]] = None,
    ) -> List[PIIEntity]:
        """
        Run context detection across multiple blocks.

        Args:
            blocks:                List of ContentBlocks to analyze.
            existing_entities_map: Map of block_id → existing entities.

        Returns:
            Combined list of all context-enhanced and new entities.
        """
        all_entities: List[PIIEntity] = []
        entities_map = existing_entities_map or {}

        for block in blocks:
            block_entities = entities_map.get(block.block_id, [])
            result = self.detect(block, existing_entities=block_entities)
            all_entities.extend(result)

        return all_entities

    def _enhance_existing_entities(
        self, text: str, entities: List[PIIEntity]
    ) -> List[PIIEntity]:
        """
        Enhance existing entities by finding context cues near their positions.

        For each entity, look in a window around its text span for
        relevant cue keywords. If found, boost confidence and record the cue.
        """
        enhanced = []
        text_lower = text.lower()

        for entity in entities:
            # Look for context cues in window around the entity
            window_start = max(0, entity.text_start - self.window_size)
            window_end = min(len(text), entity.text_end + self.window_size)
            window_text = text_lower[window_start:window_end]

            # Check cues for this entity's type
            cues_found: List[str] = []
            compiled = self._compiled_cues.get(entity.entity_type, [])
            for i, pattern in enumerate(compiled):
                if pattern.search(window_text):
                    cue_text = self.cue_patterns[entity.entity_type][i]
                    cues_found.append(cue_text)

            if cues_found:
                # Boost confidence based on number of cues found
                boost = min(0.20, 0.08 * len(cues_found))
                entity.confidence = min(1.0, entity.confidence + boost)
                entity.context_cues.extend(cues_found)
                if "context" not in entity.detection_layers:
                    entity.detection_layers.append("context")

                logger.debug(
                    "Enhanced entity %s (type=%s) with cues %s, "
                    "confidence → %.2f",
                    entity.entity_id[:20], entity.entity_type.value,
                    cues_found, entity.confidence,
                )

            enhanced.append(entity)

        return enhanced

    def _table_header_propagation(self, block: ContentBlock) -> List[PIIEntity]:
        """
        Infer entity type from table column headers.

        If a block originates from a table cell and the column header
        maps to a known entity type, create an entity for the cell value.
        """
        if not block.table_context or not block.table_context.column_headers:
            return []

        entities: List[PIIEntity] = []
        cell_text = block.text.strip()

        if not cell_text:
            return []

        for header in block.table_context.column_headers:
            header_lower = header.strip().lower()
            entity_type = self.table_header_map.get(header_lower)

            if entity_type is None:
                # Try fuzzy matching: check if any key is a substring of the header
                for key, etype in self.table_header_map.items():
                    if key in header_lower or header_lower in key:
                        entity_type = etype
                        break

            if entity_type:
                entity = PIIEntity(
                    entity_type=entity_type,
                    value=cell_text,
                    source=DetectionSource.CONTEXT,
                    detection_layers=["context"],
                    confidence=0.70,  # Table header context = moderate confidence
                    page=block.page,
                    bbox=block.bbox,
                    text_start=0,
                    text_end=len(cell_text),
                    block_id=block.block_id,
                    context_cues=[f"table_header:{header}"],
                )
                entities.append(entity)

                logger.debug(
                    "Table header '%s' → entity type %s for value '%s'",
                    header, entity_type.value, cell_text[:20],
                )

        return entities

    def _get_section_boost(self, section_context: str) -> float:
        """
        Get the confidence boost for a section heading.

        Args:
            section_context: The section heading text.

        Returns:
            Confidence boost value (0.0 if no matching trigger).
        """
        section_lower = section_context.strip().lower()

        # Exact match
        if section_lower in self.section_triggers:
            return self.section_triggers[section_lower]

        # Substring match
        for trigger, boost in self.section_triggers.items():
            if trigger in section_lower or section_lower in trigger:
                return boost

        return 0.0

    def _sliding_window_detection(self, block: ContentBlock) -> List[PIIEntity]:
        """
        Discover new entities by finding cue words followed by potential values.

        Scans text for cue patterns (e.g., "SSN: <val>", "DOB: <val>") and looks
        for values immediately after them that might be PII.
        """
        entities: List[PIIEntity] = []
        text = block.text

        for entity_type, cues in self.cue_patterns.items():
            for cue in cues:
                # Match cue with word boundaries, followed by separator (:, =, -, is) and the value
                pattern = re.compile(
                    rf"\b{re.escape(cue)}\b\s*[:=\-]?\s*(?:is\s+)?([^\s,;\n\r\t]+(?:\s+[^\s,;\n\r\t]+){{0,2}})",
                    re.IGNORECASE,
                )
                for match in pattern.finditer(text):
                    potential_value = match.group(1).strip()
                    # Strip trailing punctuation (. , ; :)
                    potential_value = potential_value.rstrip(".,;:")

                    if not potential_value or len(potential_value) < 2 or len(potential_value) > 60:
                        continue

                    # Avoid common stopwords
                    if potential_value.lower() in {
                        "the", "a", "an", "on", "in", "at", "to", "for", "of", "and", "or", "not", "is", "was",
                    }:
                        continue

                    val_start = match.start(1)
                    val_end = val_start + len(potential_value)

                    entity = PIIEntity(
                        entity_type=entity_type,
                        value=potential_value,
                        source=DetectionSource.CONTEXT,
                        detection_layers=["context"],
                        confidence=0.50,  # Context-only = moderate, needs resolution
                        page=block.page,
                        bbox=block.bbox,
                        text_start=val_start,
                        text_end=val_end,
                        block_id=block.block_id,
                        context_cues=[cue],
                    )
                    entities.append(entity)

        return entities
