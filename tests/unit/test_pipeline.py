"""
Unit Tests: Detection Pipeline Orchestrator (src/detection/pipeline.py)
======================================================================

Tests full 5-layer pipeline execution, layer toggles for ablation studies,
audit metadata generation, and integration across regex, context, validator,
and resolver layers.
"""

import pytest
from unittest.mock import MagicMock
from src.schema.entities import (
    ContentBlock,
    EntityType,
    RiskLevel,
    TableContext,
    ValidatorStatus,
)
from src.detection.pipeline import DetectionPipeline


# =============================================================================
# Full Pipeline Execution Tests
# =============================================================================

class TestPipelineExecution:
    """Test full pipeline runs with simulated and realistic inputs."""

    @pytest.fixture
    def pipeline_without_ner(self):
        """Pipeline with NER disabled to run fast without requiring large ML model download."""
        return DetectionPipeline(
            enable_regex=True,
            enable_ner=False,
            enable_context=True,
            enable_validators=True,
            enable_allow_list=True,
        )

    def test_pipeline_empty_blocks(self, pipeline_without_ner):
        result = pipeline_without_ner.run([], source_file="empty.txt")
        assert result.total_entities == 0
        assert result.detection_metadata.blocks_processed == 0
        assert result.detection_metadata.processing_time_ms >= 0

    def test_pipeline_detects_multiple_pii_types(self, pipeline_without_ner):
        blocks = [
            ContentBlock(
                text="The customer's email is jane.doe@example.com and phone is +1-202-555-0143.",
                block_id="b1",
                page=1,
            ),
            ContentBlock(
                text="SSN on file: 123-45-6789.",
                block_id="b2",
                page=1,
            ),
        ]

        result = pipeline_without_ner.run(blocks, source_file="customer_records.txt")
        assert result.total_entities >= 3
        assert result.source_file == "customer_records.txt"
        assert result.detection_metadata.blocks_processed == 2
        assert result.detection_metadata.pages_processed == 1

        types = [e.entity_type for e in result.entities]
        assert EntityType.EMAIL in types
        assert EntityType.PHONE in types
        assert EntityType.SSN in types

    def test_pipeline_table_header_propagation(self, pipeline_without_ner):
        blocks = [
            ContentBlock(
                text="4532015099991234",
                block_id="tbl_cell_1",
                page=2,
                table_context=TableContext(
                    table_id="tbl_1",
                    row_index=1,
                    col_index=2,
                    column_headers=["Credit Card Number"],
                ),
            )
        ]

        result = pipeline_without_ner.run(blocks, source_file="financial_table.pdf")
        assert result.total_entities >= 1
        card_entities = [e for e in result.entities if e.entity_type == EntityType.CARD]
        assert len(card_entities) >= 1
        assert card_entities[0].risk_level == RiskLevel.CRITICAL

    def test_pipeline_with_mocked_ner(self):
        """Test pipeline with mocked NER layer to verify layer 2 integration."""
        pipeline = DetectionPipeline(
            enable_regex=True,
            enable_ner=True,
            enable_context=True,
            enable_validators=True,
        )
        # Mock the NER engine detect_batch
        pipeline.ner_engine = MagicMock()
        mock_person = MagicMock()
        mock_person.entity_type = EntityType.PERSON
        mock_person.value = "John Doe"
        mock_person.confidence = 0.85
        mock_person.detection_layers = ["ner"]
        mock_person.block_id = "b1"
        mock_person.text_start = 0
        mock_person.text_end = 8
        mock_person.page = 1
        mock_person.bbox = None
        mock_person.risk_level = RiskLevel.MEDIUM
        mock_person.context_cues = []
        mock_person.validator_result = ValidatorStatus.NOT_APPLICABLE
        mock_person.entity_id = "mock_person_id"
        mock_person.source = MagicMock(value="ner")

        pipeline.ner_engine.detect_batch.return_value = [mock_person]

        blocks = [ContentBlock(text="John Doe submitted report", block_id="b1", page=1)]
        result = pipeline.run(blocks, source_file="report.txt")

        assert result.detection_metadata.ner_matches == 1
        assert len(result.entities) >= 1


# =============================================================================
# Ablation Mode Tests
# =============================================================================

class TestAblationModes:
    """Test disabling individual layers (used for Day 16 ablation study)."""

    def test_baseline_regex_only(self):
        """Layer 1 only (no context, no validators, no NER)."""
        pipeline = DetectionPipeline(
            enable_regex=True,
            enable_ner=False,
            enable_context=False,
            enable_validators=False,
        )
        blocks = [
            ContentBlock(
                text="Contact: user@domain.com, SSN: 123-45-6789",
                block_id="b1",
                page=1,
            )
        ]
        result = pipeline.run(blocks)
        assert result.total_entities >= 2
        for entity in result.entities:
            assert entity.detection_layers == ["regex"]
            assert entity.validator_result == ValidatorStatus.NOT_APPLICABLE

    def test_validators_ablation_modifies_confidence(self):
        """Verify that enabling validators alters confidence scores on invalid data."""
        # Unvalidated pipeline
        p_no_val = DetectionPipeline(
            enable_regex=True,
            enable_ner=False,
            enable_context=False,
            enable_validators=False,
        )
        # Validated pipeline
        p_val = DetectionPipeline(
            enable_regex=True,
            enable_ner=False,
            enable_context=False,
            enable_validators=True,
        )

        # Invalid Luhn card (4000000000000003: 4*2 + 3 = 11, mod 10 != 0)
        invalid_card = "4000000000000003"
        blocks = [ContentBlock(text=f"Card: {invalid_card}", block_id="b1", page=1)]

        res_no_val = p_no_val.run(blocks)
        res_val = p_val.run(blocks)

        card_no_val = [e for e in res_no_val.entities if e.entity_type == EntityType.CARD][0]
        card_val = [e for e in res_val.entities if e.entity_type == EntityType.CARD][0]

        assert card_val.confidence < card_no_val.confidence
        assert card_val.validator_result == ValidatorStatus.FAIL
