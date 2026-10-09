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

import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional

from src.schema.entities import (
    ContentBlock,
    DetectionResult,
    DetectionMetadata,
    PIIEntity,
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
