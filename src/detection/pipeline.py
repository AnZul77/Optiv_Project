"""
Detection Pipeline Orchestrator
================================

Orchestrates the full detection pipeline:
    Layer 1: Regex Engine     → Deterministic pattern matching
    Layer 2: NER Engine       → ML-based entity extraction  
    Layer 3: Context Engine   → Document/table-level context reasoning
    Layer 4: Validator Engine → Algorithmic confidence adjustment
    Layer 5: Entity Resolver  → Overlapping span merging & deduplication

This module provides the single entry point `DetectionPipeline.run()`
that takes a list of ContentBlocks and produces a DetectionResult.

Supports toggling individual layers for ablation experiments (Day 16).

**Ownership:** Person 3 (PII Detection & Context Engine Lead)
"""

from __future__ import annotations

import re
import logging
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from src.schema.entities import (
    ContentBlock,
    TableContext,
    DetectionResult,
    DetectionMetadata,
    PIIEntity,
    EntityType,
    DetectionSource,
)
from src.detection.context import (
    NON_PII_TERMS,
    ORGANIZATIONAL_SUFFIXES,
    EMAIL_STRICT_PATTERN,
)
from src.detection.ner import (
    DECISION_OUTCOMES,
    LEGAL_DOCUMENT_TERMS,
    STANDALONE_JURISDICTIONS,
    TOOL_COMPANY_NAMES,
    STRUCTURAL_PERSON_EXCLUSIONS,
    TEMPLATE_PERSON_PATTERNS,
)
from src.detection.regex import RegexEngine
from src.detection.ner import NEREngine
from src.detection.context import ContextEngine
from src.detection.validators import ValidatorEngine
from src.detection.resolver import EntityResolver

logger = logging.getLogger(__name__)


class DetectionPipeline:
    """
    Full PII detection pipeline orchestrator.

    Runs all 5 detection layers in sequence and produces a unified
    DetectionResult. Layers can be individually disabled for ablation.

    Usage:
        pipeline = DetectionPipeline()
        result = pipeline.run(content_blocks, source_file="document.pdf")

    Ablation mode (baseline without context/validators):
        pipeline = DetectionPipeline(
            enable_context=False,
            enable_validators=False,
            enable_allow_list=False,
        )
    """

    def __init__(
        self,
        enable_regex: bool = True,
        enable_ner: bool = True,
        enable_context: bool = True,
        enable_validators: bool = True,
        enable_allow_list: bool = True,
        custom_allow_list: Optional[List[str]] = None,
        spacy_model: str = "en_core_web_lg",
        ner_score_threshold: float = 0.35,
        overlap_threshold: float = 0.3,
    ):
        """
        Initialize the detection pipeline with configurable layers.

        Args:
            enable_regex:        Enable Layer 1 (Regex Engine).
            enable_ner:          Enable Layer 2 (NER Engine).
            enable_context:      Enable Layer 3 (Context Engine).
            enable_validators:   Enable Layer 4 (Validator Engine).
            enable_allow_list:   Enable allow-list filtering in Regex Engine.
            custom_allow_list:   Additional allow-list patterns.
            spacy_model:         spaCy model for NER (default: en_core_web_lg).
            ner_score_threshold: Minimum Presidio score threshold.
            overlap_threshold:   IoU threshold for span overlap detection.
        """
        self.enable_regex = enable_regex
        self.enable_ner = enable_ner
        self.enable_context = enable_context
        self.enable_validators = enable_validators

        # Initialize enabled layers
        self.regex_engine = (
            RegexEngine(custom_allow_list=custom_allow_list if enable_allow_list else None)
            if enable_regex
            else None
        )
        self.ner_engine = (
            NEREngine(spacy_model=spacy_model, score_threshold=ner_score_threshold)
            if enable_ner
            else None
        )
        self.context_engine = (
            ContextEngine() if enable_context else None
        )
        self.validator_engine = (
            ValidatorEngine() if enable_validators else None
        )
        self.resolver = EntityResolver(overlap_threshold=overlap_threshold)

        layers = []
        if enable_regex:
            layers.append("regex")
        if enable_ner:
            layers.append("ner")
        if enable_context:
            layers.append("context")
        if enable_validators:
            layers.append("validators")

        logger.info("DetectionPipeline initialized with layers: %s", layers)

    def run(
        self,
        blocks: List[ContentBlock],
        source_file: str = "",
        document_id: Optional[str] = None,
    ) -> DetectionResult:
        """
        Run the full detection pipeline on a set of content blocks.

        Args:
            blocks:       List of ContentBlocks from P1/P2 extraction.
            source_file:  Original filename for the result.
            document_id:  Optional document ID (auto-generated if not provided).

        Returns:
            DetectionResult containing all detected entities and metadata.
        """
        start_time = time.time()
        metadata = DetectionMetadata()
        metadata.blocks_processed = len(blocks)
        metadata.pages_processed = len(set(b.page for b in blocks))

        all_entities: List[PIIEntity] = []

        # =====================================================================
        # Layer 1: Regex Engine
        # =====================================================================
        if self.regex_engine:
            logger.info("Running Layer 1: Regex Engine on %d blocks", len(blocks))
            regex_entities = self.regex_engine.detect_batch(blocks)
            metadata.regex_matches = len(regex_entities)
            all_entities.extend(regex_entities)
            logger.info("Layer 1 complete: %d regex matches", len(regex_entities))

        # =====================================================================
        # Layer 2: NER Engine
        # =====================================================================
        if self.ner_engine:
            logger.info("Running Layer 2: NER Engine on %d blocks", len(blocks))
            ner_entities = self.ner_engine.detect_batch(blocks)
            metadata.ner_matches = len(ner_entities)
            all_entities.extend(ner_entities)
            logger.info("Layer 2 complete: %d NER matches", len(ner_entities))

        # =====================================================================
        # Layer 3: Context Engine
        # =====================================================================
        if self.context_engine:
            logger.info("Running Layer 3: Context Engine on %d blocks", len(blocks))

            # Build map of block_id → existing entities for context enhancement
            entities_by_block: Dict[str, List[PIIEntity]] = defaultdict(list)
            for entity in all_entities:
                entities_by_block[entity.block_id].append(entity)

            context_entities = self.context_engine.detect_batch(
                blocks, existing_entities_map=dict(entities_by_block)
            )

            # Context engine returns enhanced existing + new entities
            # Replace all_entities with context-enhanced versions
            new_context_only = [
                e for e in context_entities
                if e.source.value == "context" and "context" in e.detection_layers
                and len(e.detection_layers) == 1
            ]
            metadata.context_matches = len(new_context_only)

            # Replace existing entities with enhanced versions from context engine
            all_entities = context_entities
            logger.info(
                "Layer 3 complete: %d new context entities, %d total enhanced",
                len(new_context_only), len(all_entities),
            )

        # =====================================================================
        # Layer 4: Validator Engine
        # =====================================================================
        if self.validator_engine:
            logger.info("Running Layer 4: Validators on %d entities", len(all_entities))
            pre_validation = {e.entity_id: e.confidence for e in all_entities}
            all_entities = self.validator_engine.validate_batch(all_entities)
            adjustments = sum(
                1 for e in all_entities
                if pre_validation.get(e.entity_id, 0) != e.confidence
            )
            metadata.validator_adjustments = adjustments
            logger.info("Layer 4 complete: %d confidence adjustments", adjustments)

        # =====================================================================
        # Layer 5: Entity Resolver
        # =====================================================================
        logger.info("Running Layer 5: Entity Resolver on %d entities", len(all_entities))
        pre_resolve_count = len(all_entities)
        all_entities = self.resolver.resolve(all_entities)
        metadata.resolved_merges = pre_resolve_count - len(all_entities)
        logger.info(
            "Layer 5 complete: %d → %d entities (%d merges)",
            pre_resolve_count, len(all_entities), metadata.resolved_merges,
        )

        # =====================================================================
        # Precision Filtering & Document-Wide Name Propagation
        # =====================================================================
        all_entities = self._clean_and_propagate_entities(all_entities, blocks)

        # =====================================================================
        # Build Result
        # =====================================================================
        elapsed_ms = (time.time() - start_time) * 1000
        metadata.processing_time_ms = round(elapsed_ms, 2)

        result = DetectionResult(
            source_file=source_file,
            entities=all_entities,
            detection_metadata=metadata,
        )
        if document_id:
            result.document_id = document_id

        result.compute_summaries()

        logger.info(
            "Detection complete for '%s': %d entities, %s risk summary, %.0fms",
            source_file, result.total_entities, result.risk_summary, elapsed_ms,
        )

        return result

    def run_document(self, doc: Any) -> Any:
        """
        Run detection pipeline directly on a Person 1 CanonicalDocument.

        Extracts ContentBlocks from all document pages (blocks, tables, OCR text),
        runs multi-layer detection, converts detected entities into canonical
        EntityAnnotation instances, and attaches them to `doc.entities`.

        Args:
            doc: CanonicalDocument instance from Person 1 (Ingestion).

        Returns:
            The same CanonicalDocument with populated `entities` and detection metadata.
        """
        from src.schema.document import EntityAnnotation

        blocks: List[ContentBlock] = []

        # 1. Convert pages and blocks to ContentBlocks
        for page_num, page in doc.pages_dict.items():
            # Add discrete blocks
            for block in getattr(page, "blocks", []):
                blocks.append(
                    ContentBlock(
                        text=block.text,
                        block_id=block.block_id,
                        page=page_num,
                        bbox=block.bbox,
                        section_context=block.metadata.get("section", "") if hasattr(block, "metadata") else "",
                    )
                )

            # Add table cells with inherited column headers
            for table in getattr(page, "tables", []):
                # Also include table header cells as blocks for detection
                for h_idx, h_text in enumerate(getattr(table, "headers", [])):
                    if h_text and h_text.strip():
                        blocks.append(
                            ContentBlock(
                                text=h_text,
                                block_id=f"tbl_{getattr(table, 'table_index', 0)}_hdr_{h_idx}",
                                page=page_num,
                            )
                        )
                for row in getattr(table, "rows", []):
                    for cell in row:
                        blocks.append(
                            ContentBlock(
                                text=cell.text,
                                block_id=f"tbl_{getattr(table, 'table_index', 0)}_r{cell.row_idx}_c{cell.col_idx}",
                                page=page_num,
                                bbox=cell.bbox,
                                table_context=TableContext(
                                    column_headers=getattr(table, "headers", []),
                                    header_name=getattr(cell, "header_name", ""),
                                    row_index=cell.row_idx,
                                    col_index=cell.col_idx,
                                    table_id=str(getattr(table, "table_index", "")),
                                ),
                            )
                        )

            # If page has native text or OCR text without blocks, add whole page block
            if not getattr(page, "blocks", []) and getattr(page, "combined_text", ""):
                blocks.append(
                    ContentBlock(
                        text=page.combined_text,
                        block_id=f"page_{page_num}_combined",
                        page=page_num,
                    )
                )

        # 2. Run detection pipeline
        det_result = self.run(
            blocks=blocks,
            source_file=getattr(doc, "filename", ""),
            document_id=getattr(doc, "doc_id", ""),
        )

        # 3. Convert PIIEntity objects to EntityAnnotation objects
        annotations: List[EntityAnnotation] = []
        for entity in det_result.entities:
            ann = EntityAnnotation(
                entity_id=entity.entity_id,
                type=entity.entity_type.value,
                source=entity.source.value if hasattr(entity.source, "value") else str(entity.source),
                value_hash=entity.value_hash,
                page=entity.page,
                bbox=entity.bbox or [0.0, 0.0, 0.0, 0.0],
                text_start=entity.text_start,
                text_end=entity.text_end,
                confidence=entity.confidence,
                risk=entity.risk_level.value if hasattr(entity.risk_level, "value") else str(entity.risk_level),
                action=entity.action.value if hasattr(entity.action, "value") else str(entity.action),
                context={
                    "raw_value": entity.value,
                    "detection_layers": entity.detection_layers,
                    "context_cues": entity.context_cues,
                    "validator_result": entity.validator_result.value if hasattr(entity.validator_result, "value") else str(entity.validator_result),
                },
            )
            annotations.append(ann)

        doc.entities = annotations
        if hasattr(doc, "metadata") and isinstance(doc.metadata, dict):
            doc.metadata["detection_summary"] = {
                "total_entities": det_result.total_entities,
                "risk_summary": det_result.risk_summary,
                "processing_time_ms": det_result.detection_metadata.processing_time_ms,
            }

        return doc

    def _clean_and_propagate_entities(
        self, entities: List[PIIEntity], blocks: List[ContentBlock]
    ) -> List[PIIEntity]:
        """
        1. Filters out false positives (ordinary words, non-PII terms, invalid emails).
        2. Collects confirmed PERSON names and propagates them uniformly across all document blocks.
        3. Resolves and deduplicates the augmented entity list.
        """
        cleaned: List[PIIEntity] = []
        for e in entities:
            clean_val = e.value.strip(" \t\r\n-.,;:_~#*()[]{}|/\\")
            if not clean_val or len(clean_val) < 2:
                continue

            lower_val = clean_val.lower()
            norm_val = lower_val[4:].strip() if lower_val.startswith("the ") else lower_val

            # Hard filter non-PII terms
            if lower_val in NON_PII_TERMS or norm_val in NON_PII_TERMS:
                continue

            # Strict email check: MUST match email pattern
            if e.entity_type == EntityType.EMAIL:
                if not EMAIL_STRICT_PATTERN.search(clean_val):
                    continue

            # Date check: DOB must contain digits
            if e.entity_type == EntityType.DOB:
                if not any(c.isdigit() for c in clean_val) or lower_val in NON_PII_TERMS:
                    continue

            # Employee ID check: reject version numbers like v6, v6.0 or short strings
            if e.entity_type == EntityType.EMPLOYEE_ID:
                if len(clean_val) < 4 or re.match(r"^v\d+(\.\d+)?$", clean_val, re.IGNORECASE):
                    continue

            # Aadhaar check: must have 12 digits
            if e.entity_type == EntityType.AADHAAR:
                digits = re.sub(r"[^\d]", "", clean_val)
                if len(digits) != 12:
                    continue

            # Address check: reject decision outcomes, jurisdictions, legal terms, tools, or organizational suffixes
            if e.entity_type == EntityType.ADDRESS:
                has_num = any(c.isdigit() for c in clean_val)
                has_addr_term = any(
                    re.search(rf"\b{term}\b", clean_val, re.IGNORECASE) for term in [
                        "street", "st", "road", "rd", "avenue", "ave", "lane", "ln",
                        "boulevard", "blvd", "drive", "dr", "court", "ct", "crescent",
                        "cres", "way", "suite", "ste", "apt", "apartment", "building",
                        "floor", "box", "p.o.", "po box"
                    ]
                )
                if not (has_num or has_addr_term):
                    continue
                if re.match(r"^(?:used|using|use|emerging|a documented|documented|high|medium|low|for|to|with)\b", clean_val, re.IGNORECASE):
                    continue
                if (
                    lower_val in DECISION_OUTCOMES or norm_val in DECISION_OUTCOMES
                    or lower_val in LEGAL_DOCUMENT_TERMS or norm_val in LEGAL_DOCUMENT_TERMS
                    or lower_val in STANDALONE_JURISDICTIONS or norm_val in STANDALONE_JURISDICTIONS
                    or lower_val in TOOL_COMPANY_NAMES or norm_val in TOOL_COMPANY_NAMES
                    or any(re.search(rf"\b{suffix}\b", lower_val) for suffix in ORGANIZATIONAL_SUFFIXES)
                ):
                    continue

            # Person check: must not contain corporate, workflow, organizational terms, or template patterns
            if e.entity_type == EntityType.PERSON:
                if (
                    lower_val in DECISION_OUTCOMES or norm_val in DECISION_OUTCOMES
                    or lower_val in STRUCTURAL_PERSON_EXCLUSIONS or norm_val in STRUCTURAL_PERSON_EXCLUSIONS
                    or any(p.search(clean_val) for p in TEMPLATE_PERSON_PATTERNS)
                    or any(re.search(rf"\b{suffix}\b", lower_val) for suffix in ORGANIZATIONAL_SUFFIXES)
                    or any(term in lower_val for term in [
                        "workflow", "security", "tier", "privacy shield", "ironclad", "torii",
                        "cadence", "optiv", "onetrust", "template", "rule", "trigger", "condition",
                        "reviewer", "description"
                    ])
                ):
                    continue

            cleaned.append(e)

        # Collect confirmed person names
        confirmed_names: Set[str] = set()
        for e in cleaned:
            if e.entity_type == EntityType.PERSON and e.confidence >= 0.60:
                raw_val = e.value.strip(" \t\r\n-.,;:_~#*()[]{}|/\\")
                for line in raw_val.split("\n"):
                    cand = line.strip(" \t\r\n-.,;:_~#*()[]{}|/\\")
                    if not cand or len(cand) < 3:
                        continue
                    tokens = cand.split()
                    # STRICT requirement: Must be a multi-token full name (len(tokens) >= 2)
                    # Single-token words ("Launch", "Email", "Admin", "Trigger") must NEVER be added to confirmed_names
                    if len(tokens) < 2:
                        continue
                    cand_lower = cand.lower()
                    if cand_lower in NON_PII_TERMS or cand_lower in STRUCTURAL_PERSON_EXCLUSIONS or cand_lower in DECISION_OUTCOMES:
                        continue
                    # The name must NOT contain or end with organizational suffixes (group, team, committee, etc.)
                    if any(re.search(rf"\b{suffix}\b", cand_lower) for suffix in ORGANIZATIONAL_SUFFIXES):
                        continue
                    # Must not match template patterns or appendices
                    if any(p.search(cand) for p in TEMPLATE_PERSON_PATTERNS):
                        continue
                    # Each token must be capitalized (t[0].isupper()), length >= 2, and not in generic/non-PII vocabulary
                    valid_tokens = True
                    for t in tokens:
                        clean_t = t.strip(".,;:()")
                        if len(clean_t) < 2 or not clean_t[0].isupper():
                            valid_tokens = False
                            break
                        if clean_t.lower() in NON_PII_TERMS or clean_t.lower() in STRUCTURAL_PERSON_EXCLUSIONS:
                            valid_tokens = False
                            break
                    if not valid_tokens:
                        continue

                    confirmed_names.add(cand)

        if not confirmed_names:
            return cleaned

        # Propagate confirmed names across all blocks
        propagated: List[PIIEntity] = list(cleaned)
        block_entities_map: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        for e in cleaned:
            block_entities_map[e.block_id].append((e.text_start, e.text_end))

        for block in blocks:
            if not block.text or not block.text.strip():
                continue
            for name in confirmed_names:
                pattern = re.compile(rf"\b{re.escape(name)}\b", re.IGNORECASE)
                for m in pattern.finditer(block.text):
                    m_start, m_end = m.start(), m.end()
                    existing_spans = block_entities_map.get(block.block_id, [])
                    # Check if already covered by an entity in this block
                    if any(s <= m_start and m_end <= e for s, e in existing_spans):
                        continue

                    new_entity = PIIEntity(
                        entity_type=EntityType.PERSON,
                        value=block.text[m_start:m_end],
                        source=DetectionSource.CONTEXT,
                        detection_layers=["context"],
                        confidence=0.92,
                        page=block.page,
                        bbox=block.bbox,
                        text_start=m_start,
                        text_end=m_end,
                        block_id=block.block_id,
                        context_cues=["document_wide_propagation"],
                    )
                    propagated.append(new_entity)
                    existing_spans.append((m_start, m_end))

        return self.resolver.resolve(propagated)
