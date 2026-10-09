"""
Unit Tests: Entity Resolver (src/detection/resolver.py)
=======================================================

Tests overlapping span merging, type conflict resolution,
and deduplication logic.
"""

import pytest
from src.schema.entities import (
    EntityType,
    PIIEntity,
    DetectionSource,
    RiskLevel,
    ValidatorStatus,
)
from src.detection.resolver import EntityResolver


@pytest.fixture
def resolver():
    """Create an EntityResolver instance."""
    return EntityResolver(overlap_threshold=0.3)


def _make_entity(
    entity_type: EntityType,
    value: str,
    text_start: int,
    text_end: int,
    confidence: float = 0.80,
    source: DetectionSource = DetectionSource.REGEX,
    block_id: str = "block-1",
) -> PIIEntity:
    """Helper to create a PIIEntity for resolver testing."""
    return PIIEntity(
        entity_type=entity_type,
        value=value,
        source=source,
        confidence=confidence,
        text_start=text_start,
        text_end=text_end,
        block_id=block_id,
    )


class TestOverlapDetection:
    """Test overlapping span identification."""

    def test_non_overlapping_entities(self, resolver):
        """Non-overlapping entities should remain separate."""
        entities = [
            _make_entity(EntityType.SSN, "123-45-6789", 0, 11),
            _make_entity(EntityType.EMAIL, "test@test.com", 20, 33),
        ]
        resolved = resolver.resolve(entities)
        assert len(resolved) == 2

    def test_exact_overlap_merged(self, resolver):
        """Exact same span should merge into one entity."""
        entities = [
            _make_entity(EntityType.SSN, "123-45-6789", 0, 11, confidence=0.85, source=DetectionSource.REGEX),
            _make_entity(EntityType.SSN, "123-45-6789", 0, 11, confidence=0.90, source=DetectionSource.NER),
        ]
        resolved = resolver.resolve(entities)
        assert len(resolved) == 1
        assert resolved[0].confidence == 0.90  # Higher confidence kept
        assert "regex" in resolved[0].detection_layers
        assert "ner" in resolved[0].detection_layers

    def test_partial_overlap_merged(self, resolver):
        """Partially overlapping spans should merge."""
        entities = [
            _make_entity(EntityType.PERSON, "John Smith", 0, 10, confidence=0.80),
            _make_entity(EntityType.PERSON, "John", 0, 4, confidence=0.70),
        ]
        resolved = resolver.resolve(entities)
        assert len(resolved) == 1
        assert resolved[0].confidence == 0.80  # Higher confidence
        assert resolved[0].text_start == 0
        assert resolved[0].text_end == 10  # Wider span


class TestTypeConflictResolution:
    """Test entity type conflict resolution."""

    def test_critical_wins_over_high(self, resolver):
        """CRITICAL entity type should win over HIGH in overlap."""
        entities = [
            _make_entity(EntityType.SSN, "123456789", 0, 9, confidence=0.85),
            _make_entity(EntityType.PHONE, "123456789", 0, 9, confidence=0.70),
        ]
        resolved = resolver.resolve(entities)
        assert len(resolved) == 1
        assert resolved[0].entity_type == EntityType.SSN

    def test_specific_type_wins(self, resolver):
        """More specific entity type should win when same risk."""
        entities = [
            _make_entity(EntityType.EMAIL, "test@test.com", 0, 13, confidence=0.90),
            _make_entity(EntityType.PERSON, "test@test.com", 0, 13, confidence=0.60),
        ]
        resolved = resolver.resolve(entities)
        assert len(resolved) == 1
        assert resolved[0].entity_type == EntityType.EMAIL


class TestDeduplication:
    """Test exact duplicate removal."""

    def test_exact_duplicates_collapsed(self, resolver):
        """Identical entities should be collapsed to one."""
        entities = [
            _make_entity(EntityType.SSN, "123-45-6789", 0, 11, confidence=0.85),
            _make_entity(EntityType.SSN, "123-45-6789", 0, 11, confidence=0.90),
        ]
        resolved = resolver.resolve(entities)
        assert len(resolved) == 1
        assert resolved[0].confidence == 0.90

    def test_different_blocks_not_merged(self, resolver):
        """Same span but different block_ids should NOT merge."""
        entities = [
            _make_entity(EntityType.SSN, "123-45-6789", 0, 11, block_id="block-1"),
            _make_entity(EntityType.SSN, "123-45-6789", 0, 11, block_id="block-2"),
        ]
        resolved = resolver.resolve(entities)
        assert len(resolved) == 2  # Different blocks = separate entities


class TestMergeStrategy:
    """Test the merge behavior for overlapping groups."""

    def test_combined_detection_layers(self, resolver):
        """Merged entities should combine detection layers."""
        entities = [
            _make_entity(EntityType.SSN, "123-45-6789", 0, 11, source=DetectionSource.REGEX),
            _make_entity(EntityType.SSN, "123-45-6789", 0, 11, source=DetectionSource.NER),
            _make_entity(EntityType.SSN, "123-45-6789", 0, 11, source=DetectionSource.CONTEXT),
        ]
        resolved = resolver.resolve(entities)
        assert len(resolved) == 1
        layers = resolved[0].detection_layers
        assert "regex" in layers
        assert "ner" in layers
        assert "context" in layers

    def test_combined_context_cues(self, resolver):
        """Merged entities should combine context cues."""
        e1 = _make_entity(EntityType.SSN, "123-45-6789", 0, 11)
        e1.context_cues = ["SSN:"]
        e2 = _make_entity(EntityType.SSN, "123-45-6789", 0, 11, source=DetectionSource.CONTEXT)
        e2.context_cues = ["Social Security"]

        resolved = resolver.resolve([e1, e2])
        assert len(resolved) == 1
        assert "SSN:" in resolved[0].context_cues
        assert "Social Security" in resolved[0].context_cues


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_input(self, resolver):
        assert resolver.resolve([]) == []

    def test_single_entity(self, resolver):
        entities = [_make_entity(EntityType.SSN, "123-45-6789", 0, 11)]
        resolved = resolver.resolve(entities)
        assert len(resolved) == 1

    def test_many_entities_same_block(self, resolver):
        """Multiple non-overlapping entities in same block should be kept."""
        entities = [
            _make_entity(EntityType.SSN, "123-45-6789", 0, 11),
            _make_entity(EntityType.EMAIL, "test@test.com", 20, 33),
            _make_entity(EntityType.PHONE, "555-123-4567", 40, 52),
        ]
        resolved = resolver.resolve(entities)
        assert len(resolved) == 3
