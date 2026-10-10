"""
Unit Tests: NER Engine (src/detection/ner.py)
=============================================

Tests Presidio/spaCy configuration, entity mappings, custom recognizers,
and mocked/live detection pathways.
"""

from unittest.mock import MagicMock, patch
import pytest
from src.schema.entities import (
    PIIEntity,
    EntityType,
    DetectionSource,
    ContentBlock,
)
from src.detection.ner import (
    NEREngine,
    PRESIDIO_TYPE_MAP,
    SUPPORTED_PRESIDIO_ENTITIES,
)


# =============================================================================
# Type Mappings & Configuration Tests
# =============================================================================

class TestNERConfiguration:
    """Test NER engine configuration and type mappings."""

    def test_presidio_type_map_covers_core_entities(self):
        """Verify essential entity types are mapped."""
        assert PRESIDIO_TYPE_MAP["PERSON"] == EntityType.PERSON
        assert PRESIDIO_TYPE_MAP["EMAIL_ADDRESS"] == EntityType.EMAIL
        assert PRESIDIO_TYPE_MAP["PHONE_NUMBER"] == EntityType.PHONE
        assert PRESIDIO_TYPE_MAP["US_SSN"] == EntityType.SSN
        assert PRESIDIO_TYPE_MAP["LOCATION"] == EntityType.ADDRESS
        assert PRESIDIO_TYPE_MAP["IN_PAN"] == EntityType.PAN
        assert PRESIDIO_TYPE_MAP["IN_AADHAAR"] == EntityType.AADHAAR

    def test_supported_entities_match_map_keys(self):
        """Supported entities list should contain all mapped types."""
        for key in PRESIDIO_TYPE_MAP:
            assert key in SUPPORTED_PRESIDIO_ENTITIES

    def test_custom_recognizer_configs(self):
        """Verify custom recognizer configurations are structurally valid."""
        configs = NEREngine._get_custom_recognizer_configs()
        assert len(configs) >= 7

        for cfg in configs:
            assert "entity_type" in cfg
            assert "name" in cfg
            assert "patterns" in cfg
            assert "context" in cfg
            assert len(cfg["patterns"]) > 0
            for pattern in cfg["patterns"]:
                assert "name" in pattern
                assert "regex" in pattern
                assert 0.0 <= pattern["score"] <= 1.0


# =============================================================================
# NER Engine Detection Tests (Mocked)
# =============================================================================

class TestNERDetectionMocked:
    """Test detection logic using mocked Presidio analyzer."""

    @pytest.fixture
    def engine(self):
        engine = NEREngine(spacy_model="en_core_web_sm", score_threshold=0.35)
        # Mock the internal analyzer directly without needing spacy download
        engine._initialized = True
        engine._analyzer = MagicMock()
        return engine

    def test_detect_empty_or_whitespace_block(self, engine):
        """Empty block returns empty list without calling analyzer."""
        block = ContentBlock(text="", block_id="b1", page=1)
        entities = engine.detect(block)
        assert entities == []
        engine._analyzer.analyze.assert_not_called()

        block_ws = ContentBlock(text="   \n\t  ", block_id="b2", page=1)
        entities_ws = engine.detect(block_ws)
        assert entities_ws == []

    def test_detect_single_entity(self, engine):
        """Verify entity creation from Presidio RecognizerResult."""
        mock_result = MagicMock()
        mock_result.entity_type = "PERSON"
        mock_result.start = 0
        mock_result.end = 12
        mock_result.score = 0.85

        engine._analyzer.analyze.return_value = [mock_result]

        block = ContentBlock(
            text="Rahul Sharma is the manager",
            block_id="block_01",
            page=2,
            bbox=[10.0, 20.0, 100.0, 40.0],
        )

        entities = engine.detect(block)
        assert len(entities) == 1
        e = entities[0]
        assert e.entity_type == EntityType.PERSON
        assert e.value == "Rahul Sharma"
        assert e.source == DetectionSource.NER
        assert "ner" in e.detection_layers
        assert e.confidence == 0.85
        assert e.page == 2
        assert e.bbox == [10.0, 20.0, 100.0, 40.0]
        assert e.block_id == "block_01"

    def test_detect_unmapped_entity_skipped(self, engine):
        """Unmapped Presidio types are safely ignored."""
        mock_result = MagicMock()
        mock_result.entity_type = "UNKNOWN_CUSTOM_TYPE_XYZ"
        mock_result.start = 0
        mock_result.end = 5
        mock_result.score = 0.90

        engine._analyzer.analyze.return_value = [mock_result]
        block = ContentBlock(text="Hello world", block_id="b1", page=1)
        entities = engine.detect(block)
        assert len(entities) == 0

    def test_detect_batch(self, engine):
        """Batch detection aggregates entities across multiple blocks."""
        res1 = MagicMock(entity_type="PERSON", start=0, end=4, score=0.8)
        res2 = MagicMock(entity_type="EMAIL_ADDRESS", start=0, end=14, score=0.9)

        engine._analyzer.analyze.side_effect = [[res1], [res2]]

        b1 = ContentBlock(text="John works here", block_id="b1", page=1)
        b2 = ContentBlock(text="test@corp.com is active", block_id="b2", page=1)

        entities = engine.detect_batch([b1, b2])
        assert len(entities) == 2
        assert entities[0].entity_type == EntityType.PERSON
        assert entities[1].entity_type == EntityType.EMAIL

    def test_fail_closed_error_handling(self, engine):
        """If analyzer throws an exception, detect returns [] without crashing."""
        engine._analyzer.analyze.side_effect = RuntimeError("Presidio internal failure")
        block = ContentBlock(text="John Doe", block_id="b1", page=1)
        entities = engine.detect(block)
        assert entities == []
