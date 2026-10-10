"""
NER Detection Engine (Layer 2)
==============================

Machine learning-based Named Entity Recognition using Microsoft Presidio
and spaCy for detecting unstructured PII — names, addresses, organizations,
and entities that cannot be captured by deterministic regex patterns.

This layer excels at detecting:
    - Person names in narrative prose (e.g., "Rahul Sharma submitted the report")
    - Addresses in free-form text
    - Organization names that could be sensitive
    - Entities in complex sentence structures

Design Principles:
    - Uses en_core_web_lg spaCy model for best NER accuracy
    - Custom Presidio recognizers registered for Indian/UK IDs not in defaults
    - NER runs on full text blocks (not individual lines) for cross-line entities
    - Presidio entity types are mapped to our canonical EntityType enum
    - Confidence from Presidio is used as the NER component of composite score

**Ownership:** Person 3 (PII Detection & Context Engine Lead)
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from src.schema.entities import (
    PIIEntity,
    EntityType,
    DetectionSource,
    ContentBlock,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Presidio → Internal Entity Type Mapping
# =============================================================================

PRESIDIO_TYPE_MAP: Dict[str, EntityType] = {
    # Default Presidio entities
    "PERSON": EntityType.PERSON,
    "EMAIL_ADDRESS": EntityType.EMAIL,
    "PHONE_NUMBER": EntityType.PHONE,
    "US_SSN": EntityType.SSN,
    "US_PASSPORT": EntityType.PASSPORT,
    "CREDIT_CARD": EntityType.CARD,
    "US_BANK_NUMBER": EntityType.BANK_ACCOUNT,
    "US_DRIVER_LICENSE": EntityType.EMPLOYEE_ID,  # Mapped as org ID for now
    "US_ITIN": EntityType.TAX_ID,
    "LOCATION": EntityType.ADDRESS,
    "DATE_TIME": EntityType.DOB,
    "NRP": EntityType.PERSON,  # Nationality/religious/political group
    "UK_NHS": EntityType.NINO,

    # Custom recognizer types (registered by us)
    "IN_PAN": EntityType.PAN,
    "IN_AADHAAR": EntityType.AADHAAR,
    "IN_PASSPORT": EntityType.PASSPORT,
    "UK_NINO": EntityType.NINO,
    "EMPLOYEE_ID": EntityType.EMPLOYEE_ID,
    "IN_IFSC": EntityType.IFSC,
    "IN_GST": EntityType.GST,
}

# Entity types we want Presidio to detect (filter out noise)
SUPPORTED_PRESIDIO_ENTITIES: List[str] = list(PRESIDIO_TYPE_MAP.keys())


class NEREngine:
    """
    Layer 2: ML-based Named Entity Recognition using Presidio + spaCy.

    Detects unstructured PII that regex cannot reliably capture:
    person names, addresses, organizations, and complex entity structures.

    The engine initializes lazily — spaCy model and Presidio analyzer are
    loaded on first call to detect() to avoid slow import-time loading.
    """

    def __init__(self, spacy_model: str = "en_core_web_lg", score_threshold: float = 0.35):
        """
        Initialize the NER Engine.

        Args:
            spacy_model:     spaCy model to use (default: en_core_web_lg for best accuracy).
            score_threshold: Minimum Presidio score to consider a detection (0.0–1.0).
        """
        self.spacy_model_name = spacy_model
        self.score_threshold = score_threshold
        self._analyzer = None
        self._nlp = None
        self._initialized = False

    def initialize(self) -> None:
        """
        Load spaCy model and configure Presidio analyzer with custom recognizers.

        This is called lazily on first detect() call, or can be called
        explicitly for eager initialization.
        """
        if self._initialized:
            return

        try:
            import spacy
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import SpacyNlpEngine

            logger.info("Loading spaCy model: %s", self.spacy_model_name)
            self._nlp = spacy.load(self.spacy_model_name)

            # Configure Presidio with spaCy backend
            spacy_engine = SpacyNlpEngine(
                models=[{"lang_code": "en", "model_name": self.spacy_model_name}]
            )
            self._analyzer = AnalyzerEngine(nlp_engine=spacy_engine)

            # Register custom recognizers for Indian/UK IDs
            self._register_custom_recognizers()

            self._initialized = True
            logger.info(
                "NEREngine initialized with %s and %d custom recognizers",
                self.spacy_model_name,
                len(self._get_custom_recognizer_configs()),
            )

        except ImportError as e:
            logger.error(
                "NER dependencies not installed. Run: "
                "pip install presidio-analyzer spacy && "
                "python -m spacy download en_core_web_lg. Error: %s",
                e,
            )
            raise
        except OSError as e:
            logger.error(
                "spaCy model '%s' not found. Run: "
                "python -m spacy download %s. Error: %s",
                self.spacy_model_name, self.spacy_model_name, e,
            )
            raise

    def detect(self, block: ContentBlock) -> List[PIIEntity]:
        """
        Run NER detection on a content block.

        Args:
            block: ContentBlock containing text to analyze.

        Returns:
            List of PIIEntity instances detected by NER.
        """
        if not self._initialized:
            self.initialize()

        if not block.text or not block.text.strip():
            return []

        entities: List[PIIEntity] = []

        try:
            results = self._analyzer.analyze(
                text=block.text,
                entities=SUPPORTED_PRESIDIO_ENTITIES,
                language="en",
                score_threshold=self.score_threshold,
            )

            for result in results:
                # Map Presidio type to our EntityType
                entity_type = PRESIDIO_TYPE_MAP.get(result.entity_type)
                if entity_type is None:
                    logger.debug(
                        "Skipping unmapped Presidio type: %s", result.entity_type
                    )
                    continue

                # Extract the matched value from text
                value = block.text[result.start:result.end]

                entity = PIIEntity(
                    entity_type=entity_type,
                    value=value,
                    source=DetectionSource.NER,
                    detection_layers=["ner"],
                    confidence=result.score,
                    page=block.page,
                    bbox=block.bbox,
                    text_start=result.start,
                    text_end=result.end,
                    block_id=block.block_id,
                )

                entities.append(entity)

            logger.info(
                "NEREngine detected %d entities in block '%s' (page %d)",
                len(entities), block.block_id, block.page,
            )

        except Exception as e:
            logger.error(
                "NER detection failed on block '%s': %s",
                block.block_id, e,
            )
            # Fail-closed: log error but don't crash — let other layers detect
            # The fail-closed gate (P4) will evaluate overall coverage

        return entities

    def detect_batch(self, blocks: List[ContentBlock]) -> List[PIIEntity]:
        """
        Run NER detection across multiple content blocks.

        Args:
            blocks: List of ContentBlocks to analyze.

        Returns:
            Combined list of all PIIEntity instances detected.
        """
        all_entities: List[PIIEntity] = []
        for block in blocks:
            all_entities.extend(self.detect(block))
        return all_entities

    def _register_custom_recognizers(self) -> None:
        """
        Register custom Presidio recognizers for entity types not covered
        by the default Presidio configuration.

        Custom recognizers:
            - IN_PAN:       Indian Permanent Account Number
            - IN_AADHAAR:   Indian Aadhaar (12-digit UID)
            - IN_PASSPORT:  Indian Passport (letter + 7 digits)
            - UK_NINO:      UK National Insurance Number
            - EMPLOYEE_ID:  Organization employee identifiers
            - IN_IFSC:      Indian bank IFSC code
            - IN_GST:       Indian GST identification number
        """
        from presidio_analyzer import PatternRecognizer, Pattern

        for config in self._get_custom_recognizer_configs():
            recognizer = PatternRecognizer(
                supported_entity=config["entity_type"],
                name=config["name"],
                patterns=[
                    Pattern(
                        name=p["name"],
                        regex=p["regex"],
                        score=p["score"],
                    )
                    for p in config["patterns"]
                ],
                supported_language="en",
                context=config.get("context", None),
            )
            self._analyzer.registry.add_recognizer(recognizer)
            logger.debug("Registered custom recognizer: %s", config["name"])

    @staticmethod
    def _get_custom_recognizer_configs() -> List[Dict]:
        """Return configuration for all custom Presidio recognizers."""
        return [
            {
                "entity_type": "IN_PAN",
                "name": "Indian PAN Recognizer",
                "patterns": [
                    {
                        "name": "pan_strict",
                        "regex": r"\b[A-Z]{3}[PCHATBLJFG][A-Z]\d{4}[A-Z]\b",
                        "score": 0.85,
                    },
                    {
                        "name": "pan_relaxed",
                        "regex": r"\b[A-Z]{5}\d{4}[A-Z]\b",
                        "score": 0.60,
                    },
                ],
                "context": ["pan", "permanent account", "income tax", "pan card"],
            },
            {
                "entity_type": "IN_AADHAAR",
                "name": "Indian Aadhaar Recognizer",
                "patterns": [
                    {
                        "name": "aadhaar_spaced",
                        "regex": r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b",
                        "score": 0.85,
                    },
                    {
                        "name": "aadhaar_dashed",
                        "regex": r"\b[2-9]\d{3}-\d{4}-\d{4}\b",
                        "score": 0.85,
                    },
                ],
                "context": ["aadhaar", "aadhar", "uid", "unique identification"],
            },
            {
                "entity_type": "IN_PASSPORT",
                "name": "Indian Passport Recognizer",
                "patterns": [
                    {
                        "name": "in_passport",
                        "regex": r"\b[A-Z][0-9]{7}\b",
                        "score": 0.50,
                    },
                ],
                "context": ["passport", "travel document"],
            },
            {
                "entity_type": "UK_NINO",
                "name": "UK NINO Recognizer",
                "patterns": [
                    {
                        "name": "nino",
                        "regex": r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
                        "score": 0.85,
                    },
                ],
                "context": ["nino", "national insurance", "ni number"],
            },
            {
                "entity_type": "EMPLOYEE_ID",
                "name": "Employee ID Recognizer",
                "patterns": [
                    {
                        "name": "emp_id",
                        "regex": r"\bEMP[-\s]?\d{4,8}\b",
                        "score": 0.80,
                    },
                ],
                "context": ["employee", "emp id", "staff", "employee number"],
            },
            {
                "entity_type": "IN_IFSC",
                "name": "Indian IFSC Recognizer",
                "patterns": [
                    {
                        "name": "ifsc",
                        "regex": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
                        "score": 0.80,
                    },
                ],
                "context": ["ifsc", "branch code", "neft", "rtgs", "bank"],
            },
            {
                "entity_type": "IN_GST",
                "name": "Indian GST Recognizer",
                "patterns": [
                    {
                        "name": "gstin",
                        "regex": r"\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[Z][A-Z0-9]\b",
                        "score": 0.90,
                    },
                ],
                "context": ["gst", "gstin", "goods and services tax"],
            },
        ]

    @property
    def is_initialized(self) -> bool:
        """Check if the engine has been initialized."""
        return self._initialized
