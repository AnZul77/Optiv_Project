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

import re
import logging
from typing import Dict, List, Optional, Set

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

from src.detection.context import NON_PII_TERMS, ORGANIZATIONAL_SUFFIXES

# Negative filter sets
DECISION_OUTCOMES: Set[str] = {
    "approved", "rejected", "pending", "conditional", "submitted", "result",
}

LEGAL_DOCUMENT_TERMS: Set[str] = {
    "contract", "agreement", "policy", "form", "contract submission form",
    "contract creation", "intake form", "amendment",
}

STANDALONE_JURISDICTIONS: Set[str] = {
    "united states", "the united states", "u.s.", "u.s.a.", "usa", "uk",
    "canada", "united kingdom", "us", "eu", "apac", "emea", "na", "sa",
}

TOOL_COMPANY_NAMES: Set[str] = {
    "ironclad", "torii", "optiv", "cadence", "onetrust", "servicenow",
    "workday", "salesforce", "jira",
}

STRUCTURAL_PERSON_EXCLUSIONS: Set[str] = {
    "launch", "admin", "custom", "template", "templates", "trigger",
    "condition", "email", "qa reviewer", "description", "artificial intelligence",
    "security team", "annual", "rule name", "trigger name", "email id",
    "vendor tier attribute", "vendor tier",
    # Address terms to prevent misclassifying parts of addresses as PERSON
    "suite", "ste", "apt", "apartment", "unit", "floor", "fl", "room", "bldg", "building",
    # System / visual terms
    "image", "database image", "screenshot", "database snapshot",
}

TEMPLATE_PERSON_PATTERNS = [
    re.compile(r"\b(?:Due\s+Diligence\s+)?Questionnaire\b", re.IGNORECASE),
    re.compile(r"\bAppendix\s+[A-Z]\b", re.IGNORECASE),
    re.compile(r"\bT[1-3]\s+v\d+\b", re.IGNORECASE),
]


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

            try:
                logger.info("Loading spaCy model: %s", self.spacy_model_name)
                self._nlp = spacy.load(self.spacy_model_name)
                loaded_model = self.spacy_model_name
            except OSError:
                if self.spacy_model_name != "en_core_web_sm":
                    logger.warning(
                        "spaCy model '%s' not found. Falling back to 'en_core_web_sm'.",
                        self.spacy_model_name,
                    )
                    self._nlp = spacy.load("en_core_web_sm")
                    loaded_model = "en_core_web_sm"
                else:
                    raise

            # Configure Presidio with spaCy backend
            spacy_engine = SpacyNlpEngine(
                models=[{"lang_code": "en", "model_name": loaded_model}]
            )
            self._analyzer = AnalyzerEngine(nlp_engine=spacy_engine)

            # Register custom recognizers for Indian/UK IDs
            self._register_custom_recognizers()

            self._initialized = True
            logger.info(
                "NEREngine initialized with %s and %d custom recognizers",
                loaded_model,
                len(self._get_custom_recognizer_configs()),
            )

        except ImportError as e:
            logger.error(
                "NER dependencies not installed. Run: "
                "pip install presidio-analyzer spacy && "
                "python -m spacy download en_core_web_sm. Error: %s",
                e,
            )
            raise
        except OSError as e:
            logger.error(
                "spaCy model '%s' not found. Run: "
                "python -m spacy download en_core_web_sm. Error: %s",
                self.spacy_model_name, e,
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
            # 1. Extract organization and non-person entity spans using spaCy
            org_spans = set()
            if self._nlp:
                try:
                    spacy_doc = self._nlp(block.text)
                    for ent in spacy_doc.ents:
                        if ent.label_ in ("ORG", "PRODUCT", "WORK_OF_ART", "LAW"):
                            org_spans.add((ent.start_char, ent.end_char))
                except Exception as nlp_err:
                    logger.debug("spaCy span extraction note: %s", nlp_err)

            # 2. Run Presidio Analyzer
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
                clean_val = value.strip(" \t\r\n-.,;:_~#*()[]{}|/\\")

                # Discard empty, pure symbol, or single-character noise
                if not clean_val or len(clean_val) < 2:
                    continue

                # Hard filter for enterprise/domain non-PII terms
                if clean_val.lower() in NON_PII_TERMS:
                    continue

                # False positive filtering for PERSON
                if entity_type == EntityType.PERSON:
                    lower_val = clean_val.lower()
                    norm_val = lower_val[4:].strip() if lower_val.startswith("the ") else lower_val

                    # Pure numbers or all-caps short acronyms (AI, IT, SLA, TPRM) are not people
                    if clean_val.isdigit() or (clean_val.isupper() and len(clean_val) <= 4):
                        continue
                    if sum(c.isalpha() for c in clean_val) < 2:
                        continue

                    # Reject template patterns and appendices
                    if any(p.search(clean_val) for p in TEMPLATE_PERSON_PATTERNS):
                        continue

                    # Reject decision outcomes
                    if lower_val in DECISION_OUTCOMES or norm_val in DECISION_OUTCOMES:
                        continue

                    # Reject structural labels and common verbs/nouns
                    if lower_val in STRUCTURAL_PERSON_EXCLUSIONS or norm_val in STRUCTURAL_PERSON_EXCLUSIONS:
                        continue
                    if lower_val in NON_PII_TERMS or norm_val in NON_PII_TERMS:
                        continue

                    # Reject organizational units: any entity ending with or containing group, team, etc.
                    if any(re.search(rf"\b{suffix}\b", lower_val) for suffix in ORGANIZATIONAL_SUFFIXES):
                        continue

                    # Reject operational rule codes, prefixes, or underscores
                    if "_" in clean_val or any(clean_val.startswith(p) for p in ("QRC_", "QRN_", "QR_", "QR.", "WR.", "CL.", "SLA.", "CD_", "CTL-", "RSK-")):
                        continue

                    # Filter out terms containing non-PII keywords
                    if any(term in lower_val for term in ["workflow", "security", "tier", "privacy shield", "ironclad", "torii", "cadence", "optiv", "onetrust", "template", "rule", "trigger", "condition", "reviewer"]):
                        continue

                    # Check if this span was classified as an Organization by spaCy
                    if any(s <= result.start < e or result.start <= s < result.end for s, e in org_spans):
                        logger.debug("Filtered out ORG entity misclassified as PERSON: '%s'", clean_val)
                        continue

                    # Common enterprise organizations and tech brands
                    if clean_val.lower() in {"optiv", "onetrust", "cadence", "microsoft", "google", "apple", "amazon"}:
                        continue

                    # Single capitalized token without surname acting as corporate subject
                    words = clean_val.split()
                    if len(words) == 1 and result.score < 0.88:
                        after_text = block.text[result.end:result.end + 50].lower()
                        if any(w in after_text for w in [
                            "is the", "delivering", "advisory", "solutions", "partner", "technologies",
                            "services", "inc", "llc", "corp", "group", "platform", "software",
                        ]):
                            logger.debug("Filtered out corporate subject: '%s'", clean_val)
                            continue

                    # If Presidio/spaCy lumped multiple names separated by newlines
                    if "\n" in value:
                        sub_parts = [line.strip() for line in value.split("\n") if line.strip()]
                        for sub in sub_parts:
                            clean_sub = sub.strip(" \t\r\n-.,;:_~#*()[]{}|/\\")
                            sub_lower = clean_sub.lower()
                            if not clean_sub or len(clean_sub) < 2 or sub_lower in NON_PII_TERMS or sum(c.isalpha() for c in clean_sub) < 2:
                                continue
                            if any(p.search(clean_sub) for p in TEMPLATE_PERSON_PATTERNS):
                                continue
                            if sub_lower in DECISION_OUTCOMES or sub_lower in STRUCTURAL_PERSON_EXCLUSIONS:
                                continue
                            if any(re.search(rf"\b{suffix}\b", sub_lower) for suffix in ORGANIZATIONAL_SUFFIXES):
                                continue
                            if any(term in sub_lower for term in ["workflow", "security", "tier", "privacy shield"]):
                                continue
                            sub_start = block.text.find(sub, result.start)
                            if sub_start == -1:
                                sub_start = result.start
                            sub_end = sub_start + len(sub)
                            entities.append(PIIEntity(
                                entity_type=EntityType.PERSON,
                                value=sub,
                                source=DetectionSource.NER,
                                detection_layers=["ner"],
                                confidence=result.score,
                                page=block.page,
                                bbox=block.bbox,
                                text_start=sub_start,
                                text_end=sub_end,
                                block_id=block.block_id,
                            ))
                        continue

                # False positive filtering for ADDRESS
                if entity_type == EntityType.ADDRESS:
                    lower_addr = clean_val.lower()
                    norm_addr = lower_addr[4:].strip() if lower_addr.startswith("the ") else lower_addr

                    # Reject decision outcomes
                    if lower_addr in DECISION_OUTCOMES or norm_addr in DECISION_OUTCOMES:
                        continue
                    # Reject legal / document terms
                    if lower_addr in LEGAL_DOCUMENT_TERMS or norm_addr in LEGAL_DOCUMENT_TERMS:
                        continue
                    # Reject standalone countries / jurisdictions
                    if lower_addr in STANDALONE_JURISDICTIONS or norm_addr in STANDALONE_JURISDICTIONS:
                        continue
                    # Reject tool / company names
                    if lower_addr in TOOL_COMPANY_NAMES or norm_addr in TOOL_COMPANY_NAMES:
                        continue
                    # Reject general non-PII terms
                    if lower_addr in NON_PII_TERMS or norm_addr in NON_PII_TERMS:
                        continue
                    # Reject operational prefixes and underscores
                    if "_" in clean_val or any(clean_val.startswith(p) for p in ("QRC_", "QRN_", "QR_", "QR.", "WR.", "CL.", "SLA.", "CD_", "CTL-", "RSK-")):
                        continue
                    # An address cannot be a single token without numbers (e.g. cursor, notify, ownership)
                    if len(clean_val.split()) < 2 and not any(c.isdigit() for c in clean_val):
                        continue
                    # Standalone country/acronym codes and short tokens
                    if lower_addr in {"ai", "us", "uk", "eu", "apac", "emea", "na", "sa"} or len(clean_val) <= 2:
                        continue

                # Strict validation for EMAIL
                if entity_type == EntityType.EMAIL:
                    if "@" not in clean_val or not re.search(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", clean_val):
                        continue

                # False positive filtering for DOB
                if entity_type == EntityType.DOB:
                    # Generic full paragraphs or long text blocks are not birth dates
                    if len(clean_val) > 35 or not any(c.isdigit() for c in clean_val):
                        continue

                # False positive filtering for EMPLOYEE_ID
                if entity_type == EntityType.EMPLOYEE_ID:
                    if len(clean_val) < 4 or re.match(r"^v\d+(\.\d+)?$", clean_val, re.IGNORECASE):
                        continue

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

            # Detect initials names pattern (e.g. KC Burney, DK Koran, M. Vossberg, A. Okonkwo-Bell) in block text
            initial_pattern = re.compile(r"\b[A-Z]{1,2}\.?\s+[A-Z][a-z]+(?:-[A-Z][a-z]+)?\b")
            for m in initial_pattern.finditer(block.text):
                cand_name = m.group(0).strip()
                cand_lower = cand_name.lower()
                if (
                    cand_lower not in NON_PII_TERMS
                    and cand_lower not in STRUCTURAL_PERSON_EXCLUSIONS
                    and cand_lower not in DECISION_OUTCOMES
                    and not any(p.search(cand_name) for p in TEMPLATE_PERSON_PATTERNS)
                    and not any(re.search(rf"\b{suffix}\b", cand_lower) for suffix in ORGANIZATIONAL_SUFFIXES)
                    and not any(s <= m.start() < e for s, e in org_spans)
                ):
                    # Check if already covered
                    if not any(e.text_start <= m.start() and m.end() <= e.text_end for e in entities):
                        entities.append(PIIEntity(
                            entity_type=EntityType.PERSON,
                            value=cand_name,
                            source=DetectionSource.NER,
                            detection_layers=["ner"],
                            confidence=0.88,
                            page=block.page,
                            bbox=block.bbox,
                            text_start=m.start(),
                            text_end=m.end(),
                            block_id=block.block_id,
                        ))

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
