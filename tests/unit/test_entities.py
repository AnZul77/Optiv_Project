"""
Unit Tests: Entity Schema (src/schema/entities.py)
===================================================

Tests the canonical data models, enums, risk mapping,
confidence weights, and entity utility methods.
"""

import pytest
from src.schema.entities import (
    EntityType,
    RiskLevel,
    Action,
    DetectionSource,
    ValidatorStatus,
    PIIEntity,
    DetectionResult,
    DetectionMetadata,
    ConfidenceWeights,
    ContentBlock,
    TableContext,
    RISK_MAPPING,
    compute_value_hash,
    set_hash_salt,
)


class TestEntityType:
    """Test the EntityType enum."""

    def test_all_entity_types_defined(self):
        """All 21 entity types from the taxonomy must exist."""
        expected_types = [
            "PERSON", "DOB", "ADDRESS", "EMAIL", "PHONE",
            "EMPLOYEE_ID", "DIRECTOR_ID", "SSN", "PASSPORT",
            "PAN", "AADHAAR", "TAX_ID", "NINO", "CARD",
            "BANK_ACCOUNT", "IFSC", "GST", "UPI",
            "SIGNATURE", "FACE_PHOTO", "SENSITIVE_SCREENSHOT",
        ]
        for type_name in expected_types:
            assert hasattr(EntityType, type_name), f"Missing EntityType: {type_name}"

    def test_entity_type_is_string(self):
        """EntityType values should be strings (for JSON serialization)."""
        assert EntityType.SSN.value == "SSN"
        assert EntityType.EMAIL.value == "EMAIL"
        assert isinstance(EntityType.PERSON.value, str)


class TestRiskMapping:
    """Test the RISK_MAPPING configuration."""

    def test_critical_entities(self):
        """SSN, Passport, PAN, Aadhaar, Card, NINO must be CRITICAL."""
        critical_types = [
            EntityType.SSN, EntityType.PASSPORT, EntityType.PAN,
            EntityType.AADHAAR, EntityType.CARD, EntityType.NINO,
        ]
        for entity_type in critical_types:
            assert RISK_MAPPING[entity_type] == RiskLevel.CRITICAL, (
                f"{entity_type.value} should be CRITICAL"
            )

    def test_high_entities(self):
        """Person, Email, Phone, DOB, Address, Employee ID must be HIGH."""
        high_types = [
            EntityType.PERSON, EntityType.EMAIL, EntityType.PHONE,
            EntityType.DOB, EntityType.ADDRESS, EntityType.EMPLOYEE_ID,
        ]
        for entity_type in high_types:
            assert RISK_MAPPING[entity_type] == RiskLevel.HIGH, (
                f"{entity_type.value} should be HIGH"
            )

    def test_medium_entities(self):
        """IFSC, GST, UPI must be MEDIUM."""
        medium_types = [EntityType.IFSC, EntityType.GST, EntityType.UPI]
        for entity_type in medium_types:
            assert RISK_MAPPING[entity_type] == RiskLevel.MEDIUM, (
                f"{entity_type.value} should be MEDIUM"
            )

    def test_all_types_have_risk(self):
        """Every EntityType should have a risk mapping."""
        for entity_type in EntityType:
            assert entity_type in RISK_MAPPING, (
                f"{entity_type.value} missing from RISK_MAPPING"
            )


class TestPIIEntity:
    """Test the PIIEntity dataclass."""

    def test_auto_hash(self):
        """Value hash should be auto-computed from value."""
        entity = PIIEntity(entity_type=EntityType.SSN, value="123-45-6789")
        assert entity.value_hash != ""
        assert len(entity.value_hash) == 64  # SHA-256 hex

    def test_auto_risk_level(self):
        """Risk level should be auto-assigned from entity type."""
        entity = PIIEntity(entity_type=EntityType.SSN, value="test")
        assert entity.risk_level == RiskLevel.CRITICAL

        entity2 = PIIEntity(entity_type=EntityType.EMAIL, value="test@test.com")
        assert entity2.risk_level == RiskLevel.HIGH

    def test_auto_detection_layers(self):
        """Source should be auto-added to detection_layers."""
        entity = PIIEntity(
            entity_type=EntityType.EMAIL,
            value="test@test.com",
            source=DetectionSource.REGEX,
        )
        assert "regex" in entity.detection_layers

    def test_uuid_generated(self):
        """Each entity should get a unique UUID."""
        e1 = PIIEntity(entity_type=EntityType.SSN, value="test1")
        e2 = PIIEntity(entity_type=EntityType.SSN, value="test2")
        assert e1.entity_id != e2.entity_id
        assert e1.entity_id.startswith("urn:uuid:")

    def test_audit_dict_excludes_value(self):
        """Audit dict must NOT contain raw PII value."""
        entity = PIIEntity(entity_type=EntityType.SSN, value="123-45-6789")
        audit = entity.to_audit_dict()
        assert "value" not in audit
        assert "value_hash" in audit
        assert audit["entity_type"] == "SSN"

    def test_display_dict_masks_value(self):
        """Display dict should show masked preview, not raw value."""
        entity = PIIEntity(entity_type=EntityType.SSN, value="123-45-6789")
        display = entity.to_display_dict()
        assert display["masked_value"] != "123-45-6789"
        assert "•" in display["masked_value"]

    def test_mask_value(self):
        """Test value masking utility."""
        assert PIIEntity._mask_value("ab") == "••"
        assert PIIEntity._mask_value("abc") == "a••c"
        assert PIIEntity._mask_value("abcdef") == "a••••f"

    def test_merge_with(self):
        """Merging two entities should combine layers and keep best confidence."""
        e1 = PIIEntity(
            entity_type=EntityType.SSN,
            value="123-45-6789",
            source=DetectionSource.REGEX,
            confidence=0.85,
            text_start=10,
            text_end=21,
            context_cues=["SSN:"],
        )
        e2 = PIIEntity(
            entity_type=EntityType.SSN,
            value="123-45-6789",
            source=DetectionSource.NER,
            confidence=0.90,
            text_start=10,
            text_end=21,
            context_cues=["Social Security"],
        )
        merged = e1.merge_with(e2)

        assert merged.confidence == 0.90
        assert "regex" in merged.detection_layers
        assert "ner" in merged.detection_layers
        assert "SSN:" in merged.context_cues
        assert "Social Security" in merged.context_cues


class TestDetectionResult:
    """Test the DetectionResult dataclass."""

    def test_compute_summaries(self):
        """Summaries should be computed from entities."""
        entities = [
            PIIEntity(entity_type=EntityType.SSN, value="123-45-6789", confidence=0.95),
            PIIEntity(entity_type=EntityType.SSN, value="987-65-4321", confidence=0.90),
            PIIEntity(entity_type=EntityType.EMAIL, value="test@test.com", confidence=0.95),
        ]
        result = DetectionResult(entities=entities)
        result.compute_summaries()

        assert result.total_entities == 3
        assert result.entity_type_counts["SSN"] == 2
        assert result.entity_type_counts["EMAIL"] == 1
        assert result.risk_summary["CRITICAL"] == 2
        assert result.risk_summary["HIGH"] == 1

    def test_get_critical_entities(self):
        """Should filter only CRITICAL risk entities."""
        entities = [
            PIIEntity(entity_type=EntityType.SSN, value="test"),
            PIIEntity(entity_type=EntityType.EMAIL, value="test@test.com"),
            PIIEntity(entity_type=EntityType.PAN, value="ABCDE1234F"),
        ]
        result = DetectionResult(entities=entities)
        critical = result.get_critical_entities()
        assert len(critical) == 2  # SSN + PAN

    def test_has_unresolved_critical(self):
        """Should detect low-confidence critical entities."""
        entities = [
            PIIEntity(entity_type=EntityType.SSN, value="test", confidence=0.50),
        ]
        result = DetectionResult(entities=entities)
        assert result.has_unresolved_critical() is True

    def test_no_unresolved_when_high_confidence(self):
        """High-confidence critical entities should not flag unresolved."""
        entities = [
            PIIEntity(entity_type=EntityType.SSN, value="test", confidence=0.95),
        ]
        result = DetectionResult(entities=entities)
        assert result.has_unresolved_critical() is False


class TestConfidenceWeights:
    """Test the ConfidenceWeights configuration."""

    def test_default_weights_sum_to_one(self):
        """Default weights must sum to 1.0."""
        weights = ConfidenceWeights()
        total = weights.w_regex + weights.w_ner + weights.w_context + weights.w_validator + weights.w_structure
        assert abs(total - 1.0) < 0.01

    def test_compute(self):
        """Composite confidence should be weighted sum."""
        weights = ConfidenceWeights()
        score = weights.compute(
            regex_score=1.0, ner_score=1.0, context_score=1.0,
            validator_score=1.0, structure_score=1.0,
        )
        assert abs(score - 1.0) < 0.01

    def test_compute_clamps(self):
        """Confidence should be clamped to [0.0, 1.0]."""
        weights = ConfidenceWeights()
        assert weights.compute(regex_score=0.0) >= 0.0
        assert weights.compute(regex_score=5.0) <= 1.0

    def test_invalid_weights_raise(self):
        """Weights that don't sum to 1.0 should raise ValueError."""
        with pytest.raises(ValueError):
            ConfidenceWeights(w_regex=0.5, w_ner=0.5, w_context=0.5)


class TestValueHash:
    """Test the value hashing utility."""

    def test_hash_consistency(self):
        """Same value should always produce same hash."""
        h1 = compute_value_hash("123-45-6789")
        h2 = compute_value_hash("123-45-6789")
        assert h1 == h2

    def test_hash_uniqueness(self):
        """Different values should produce different hashes."""
        h1 = compute_value_hash("123-45-6789")
        h2 = compute_value_hash("987-65-4321")
        assert h1 != h2

    def test_hash_length(self):
        """SHA-256 hex should be 64 characters."""
        h = compute_value_hash("test")
        assert len(h) == 64
