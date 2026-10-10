"""
Unit Tests: Context Engine (src/detection/context.py)
=====================================================

Tests context cue detection, window proximity boosting, table header
propagation, section-level triggers, and sliding window entity discovery.
"""

import pytest
from src.schema.entities import (
    PIIEntity,
    EntityType,
    DetectionSource,
    ContentBlock,
    TableContext,
)
from src.detection.context import (
    ContextEngine,
    CUE_PATTERNS,
    SECTION_TRIGGERS,
    TABLE_HEADER_MAP,
)


@pytest.fixture
def engine():
    return ContextEngine(window_size=80)


# =============================================================================
# Cue Pattern & Table Header Map Definitions
# =============================================================================

class TestContextDefinitions:
    """Test cue patterns, section triggers, and table headers."""

    def test_cue_patterns_defined_for_core_types(self):
        assert EntityType.SSN in CUE_PATTERNS
        assert EntityType.PAN in CUE_PATTERNS
        assert EntityType.AADHAAR in CUE_PATTERNS
        assert EntityType.EMAIL in CUE_PATTERNS
        assert EntityType.PHONE in CUE_PATTERNS
        assert EntityType.DOB in CUE_PATTERNS
        assert EntityType.CARD in CUE_PATTERNS
        assert EntityType.BANK_ACCOUNT in CUE_PATTERNS

    def test_section_triggers_defined(self):
        assert "personal information" in SECTION_TRIGGERS
        assert "employee details" in SECTION_TRIGGERS
        assert SECTION_TRIGGERS["personal information"] > 0.0

    def test_table_headers_mapped(self):
        assert TABLE_HEADER_MAP["ssn"] == EntityType.SSN
        assert TABLE_HEADER_MAP["email"] == EntityType.EMAIL
        assert TABLE_HEADER_MAP["pan"] == EntityType.PAN
        assert TABLE_HEADER_MAP["phone number"] == EntityType.PHONE


# =============================================================================
# Existing Entity Enhancement Tests
# =============================================================================

class TestEnhanceExistingEntities:
    """Test confidence boosting for existing entities with nearby cues."""

    def test_boost_with_single_cue(self, engine):
        text = "Employee Social Security Number: 123-45-6789 on record."
        val = "123-45-6789"
        idx = text.index(val)
        entity = PIIEntity(
            entity_type=EntityType.SSN,
            value=val,
            source=DetectionSource.REGEX,
            confidence=0.80,
            text_start=idx,
            text_end=idx + len(val),
            detection_layers=["regex"],
        )

        block = ContentBlock(text=text, block_id="b1", page=1)
        results = engine.detect(block, existing_entities=[entity])

        enhanced = [e for e in results if e.entity_id == entity.entity_id][0]
        assert enhanced.confidence > 0.80
        assert "context" in enhanced.detection_layers
        assert len(enhanced.context_cues) > 0

    def test_no_boost_when_no_relevant_cues(self, engine):
        text = "The code is 123-45-6789 without hints."
        val = "123-45-6789"
        idx = text.index(val)
        entity = PIIEntity(
            entity_type=EntityType.SSN,
            value=val,
            source=DetectionSource.REGEX,
            confidence=0.80,
            text_start=idx,
            text_end=idx + len(val),
            detection_layers=["regex"],
        )

        block = ContentBlock(text=text, block_id="b1", page=1)
        results = engine.detect(block, existing_entities=[entity])
        enhanced = [e for e in results if e.entity_id == entity.entity_id][0]
        assert enhanced.confidence == 0.80
        assert "context" not in enhanced.detection_layers

    def test_cue_outside_window_not_detected(self):
        engine_short = ContextEngine(window_size=5)
        text = "SSN: " + ("x" * 50) + " 123-45-6789"
        val = "123-45-6789"
        idx = text.index(val)
        entity = PIIEntity(
            entity_type=EntityType.SSN,
            value=val,
            source=DetectionSource.REGEX,
            confidence=0.80,
            text_start=idx,
            text_end=idx + len(val),
        )

        block = ContentBlock(text=text, block_id="b1", page=1)
        results = engine_short.detect(block, existing_entities=[entity])
        enhanced = [e for e in results if e.entity_id == entity.entity_id][0]
        assert enhanced.confidence == 0.80


# =============================================================================
# Table Header Propagation Tests
# =============================================================================

class TestTableHeaderPropagation:
    """Test entity discovery from table column headers."""

    def test_exact_table_header_propagation(self, engine):
        block = ContentBlock(
            text="4532-1111-2222-3333",
            block_id="cell_01",
            page=1,
            table_context=TableContext(
                table_id="tbl_1",
                row_index=1,
                col_index=2,
                column_headers=["Credit Card"],
            ),
        )

        results = engine.detect(block)
        card_entities = [e for e in results if e.entity_type == EntityType.CARD]
        assert len(card_entities) >= 1
        assert card_entities[0].source == DetectionSource.CONTEXT
        assert card_entities[0].confidence == 0.70
        assert "table_header:Credit Card" in card_entities[0].context_cues

    def test_fuzzy_table_header_propagation(self, engine):
        block = ContentBlock(
            text="user@company.com",
            block_id="cell_02",
            page=1,
            table_context=TableContext(
                table_id="tbl_1",
                row_index=1,
                col_index=3,
                column_headers=["Primary Email Address"],
            ),
        )

        results = engine.detect(block)
        email_entities = [e for e in results if e.entity_type == EntityType.EMAIL]
        assert len(email_entities) >= 1


# =============================================================================
# Section Triggers & Sliding Window Tests
# =============================================================================

class TestSectionTriggersAndSlidingWindow:
    """Test section-level boosts and sliding window cue discovery."""

    def test_section_level_boost_applied(self, engine):
        entity = PIIEntity(
            entity_type=EntityType.PERSON,
            value="John Smith",
            source=DetectionSource.NER,
            confidence=0.70,
            text_start=0,
            text_end=10,
        )

        block = ContentBlock(
            text="John Smith",
            block_id="b_sec",
            page=1,
            section_context="Employee Personal Information",
        )

        results = engine.detect(block, existing_entities=[entity])
        target = [e for e in results if e.entity_id == entity.entity_id][0]
        # Base 0.70 + section boost 0.25 = 0.95
        assert target.confidence >= 0.90
        assert any("section:" in cue for cue in target.context_cues)

    def test_sliding_window_discover_new_entity(self, engine):
        block = ContentBlock(
            text="Please note the DOB: 15/08/1990 in your records.",
            block_id="b_dob",
            page=1,
        )

        results = engine.detect(block)
        dob_entities = [e for e in results if e.entity_type == EntityType.DOB]
        assert len(dob_entities) >= 1
        assert dob_entities[0].source == DetectionSource.CONTEXT
        assert dob_entities[0].confidence == 0.50

    def test_detect_batch(self, engine):
        b1 = ContentBlock(text="No PII here", block_id="b1", page=1)
        b2 = ContentBlock(text="PAN: ABCDE1234F", block_id="b2", page=1)

        results = engine.detect_batch([b1, b2])
        assert len(results) >= 1
        assert any(e.entity_type == EntityType.PAN for e in results)
