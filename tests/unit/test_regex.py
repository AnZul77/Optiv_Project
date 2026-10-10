"""
Unit Tests: Regex Engine (src/detection/regex.py)
=================================================

Tests deterministic pattern matching for all PII entity types,
allow-list filtering, and context-gating behavior.
"""

import pytest
from src.schema.entities import EntityType, ContentBlock
from src.detection.regex import RegexEngine


@pytest.fixture
def engine():
    """Create a default RegexEngine instance."""
    return RegexEngine()


def _make_block(text: str, block_id: str = "test-block", page: int = 1) -> ContentBlock:
    """Helper to create a ContentBlock from text."""
    return ContentBlock(block_id=block_id, text=text, page=page, source_type="native_text")


# =============================================================================
# SSN Detection
# =============================================================================

class TestSSNDetection:
    """Test SSN regex patterns."""

    def test_ssn_with_dashes(self, engine):
        block = _make_block("SSN: 123-45-6789")
        entities = engine.detect(block)
        ssn_entities = [e for e in entities if e.entity_type == EntityType.SSN]
        assert len(ssn_entities) >= 1
        assert ssn_entities[0].value == "123-45-6789"
        assert ssn_entities[0].confidence >= 0.85

    def test_ssn_with_spaces(self, engine):
        block = _make_block("Social Security: 123 45 6789")
        entities = engine.detect(block)
        ssn_entities = [e for e in entities if e.entity_type == EntityType.SSN]
        assert len(ssn_entities) >= 1

    def test_ssn_invalid_area_000(self, engine):
        """SSN starting with 000 should NOT match."""
        block = _make_block("SSN: 000-12-3456")
        entities = engine.detect(block)
        ssn_entities = [e for e in entities if e.entity_type == EntityType.SSN]
        assert len(ssn_entities) == 0

    def test_ssn_invalid_area_666(self, engine):
        """SSN starting with 666 should NOT match."""
        block = _make_block("SSN: 666-12-3456")
        entities = engine.detect(block)
        ssn_entities = [e for e in entities if e.entity_type == EntityType.SSN]
        assert len(ssn_entities) == 0

    def test_ssn_invalid_area_900(self, engine):
        """SSN with area 900+ should NOT match."""
        block = _make_block("SSN: 900-12-3456")
        entities = engine.detect(block)
        ssn_entities = [e for e in entities if e.entity_type == EntityType.SSN]
        assert len(ssn_entities) == 0

    def test_multiple_ssns(self, engine):
        block = _make_block("SSNs: 123-45-6789 and 456-78-9012")
        entities = engine.detect(block)
        ssn_entities = [e for e in entities if e.entity_type == EntityType.SSN]
        assert len(ssn_entities) >= 2


# =============================================================================
# Email Detection
# =============================================================================

class TestEmailDetection:
    """Test email regex patterns."""

    def test_standard_email(self, engine):
        block = _make_block("Contact: john.doe@company.com")
        entities = engine.detect(block)
        email_entities = [e for e in entities if e.entity_type == EntityType.EMAIL]
        assert len(email_entities) == 1
        assert email_entities[0].value == "john.doe@company.com"

    def test_email_with_plus(self, engine):
        block = _make_block("Email: user+tag@domain.co.uk")
        entities = engine.detect(block)
        email_entities = [e for e in entities if e.entity_type == EntityType.EMAIL]
        assert len(email_entities) >= 1

    def test_indian_email(self, engine):
        block = _make_block("Email: rahul.sharma@tcs.co.in")
        entities = engine.detect(block)
        email_entities = [e for e in entities if e.entity_type == EntityType.EMAIL]
        assert len(email_entities) >= 1


# =============================================================================
# Phone Detection
# =============================================================================

class TestPhoneDetection:
    """Test phone regex patterns."""

    def test_us_phone_with_parens(self, engine):
        block = _make_block("Phone: (555) 123-4567")
        entities = engine.detect(block)
        phone_entities = [e for e in entities if e.entity_type == EntityType.PHONE]
        assert len(phone_entities) >= 1

    def test_international_phone(self, engine):
        block = _make_block("Phone: +1 555-123-4567")
        entities = engine.detect(block)
        phone_entities = [e for e in entities if e.entity_type == EntityType.PHONE]
        assert len(phone_entities) >= 1

    def test_indian_phone(self, engine):
        block = _make_block("Mobile: +91-98765-43210")
        entities = engine.detect(block)
        phone_entities = [e for e in entities if e.entity_type == EntityType.PHONE]
        assert len(phone_entities) >= 1


# =============================================================================
# PAN Detection
# =============================================================================

class TestPANDetection:
    """Test Indian PAN card regex patterns."""

    def test_valid_pan_individual(self, engine):
        block = _make_block("PAN: ABCPE1234F")
        entities = engine.detect(block)
        pan_entities = [e for e in entities if e.entity_type == EntityType.PAN]
        assert len(pan_entities) >= 1

    def test_valid_pan_company(self, engine):
        block = _make_block("PAN: AABCE1234F")
        entities = engine.detect(block)
        pan_entities = [e for e in entities if e.entity_type == EntityType.PAN]
        assert len(pan_entities) >= 1


# =============================================================================
# Aadhaar Detection
# =============================================================================

class TestAadhaarDetection:
    """Test Indian Aadhaar regex patterns."""

    def test_aadhaar_with_spaces(self, engine):
        block = _make_block("Aadhaar: 2345 6789 0123")
        entities = engine.detect(block)
        aadhaar_entities = [e for e in entities if e.entity_type == EntityType.AADHAAR]
        assert len(aadhaar_entities) >= 1

    def test_aadhaar_with_dashes(self, engine):
        block = _make_block("Aadhaar: 2345-6789-0123")
        entities = engine.detect(block)
        aadhaar_entities = [e for e in entities if e.entity_type == EntityType.AADHAAR]
        assert len(aadhaar_entities) >= 1

    def test_aadhaar_cannot_start_with_0_or_1(self, engine):
        """Aadhaar numbers starting with 0 or 1 should NOT match."""
        block = _make_block("Aadhaar: 0345 6789 0123")
        entities = engine.detect(block)
        aadhaar_entities = [e for e in entities if e.entity_type == EntityType.AADHAAR]
        assert len(aadhaar_entities) == 0


# =============================================================================
# Card Detection
# =============================================================================

class TestCardDetection:
    """Test credit/debit card regex patterns."""

    def test_visa_card(self, engine):
        block = _make_block("Card: 4111 1111 1111 1111")
        entities = engine.detect(block)
        card_entities = [e for e in entities if e.entity_type == EntityType.CARD]
        assert len(card_entities) >= 1

    def test_mastercard(self, engine):
        block = _make_block("Card: 5500-0000-0000-0004")
        entities = engine.detect(block)
        card_entities = [e for e in entities if e.entity_type == EntityType.CARD]
        assert len(card_entities) >= 1


# =============================================================================
# Employee ID Detection
# =============================================================================

class TestEmployeeIDDetection:
    """Test employee ID regex patterns."""

    def test_emp_with_dash(self, engine):
        block = _make_block("Employee ID: EMP-4521")
        entities = engine.detect(block)
        emp_entities = [e for e in entities if e.entity_type == EntityType.EMPLOYEE_ID]
        assert len(emp_entities) >= 1

    def test_emp_without_dash(self, engine):
        block = _make_block("Employee ID: EMP4521")
        entities = engine.detect(block)
        emp_entities = [e for e in entities if e.entity_type == EntityType.EMPLOYEE_ID]
        assert len(emp_entities) >= 1


# =============================================================================
# IFSC, GST, NINO Detection
# =============================================================================

class TestFinancialIDs:
    """Test IFSC, GST, and NINO patterns."""

    def test_ifsc_code(self, engine):
        block = _make_block("IFSC: SBIN0001234")
        entities = engine.detect(block)
        ifsc_entities = [e for e in entities if e.entity_type == EntityType.IFSC]
        assert len(ifsc_entities) >= 1

    def test_gst_number(self, engine):
        block = _make_block("GSTIN: 27AABCU9603R1ZM")
        entities = engine.detect(block)
        gst_entities = [e for e in entities if e.entity_type == EntityType.GST]
        assert len(gst_entities) >= 1

    def test_nino(self, engine):
        block = _make_block("NINO: AB 12 34 56 C")
        entities = engine.detect(block)
        nino_entities = [e for e in entities if e.entity_type == EntityType.NINO]
        assert len(nino_entities) >= 1


# =============================================================================
# Allow-List Tests (False Positive Prevention)
# =============================================================================

class TestAllowList:
    """Test that business codes are NOT detected as PII."""

    def test_incident_reference(self, engine):
        block = _make_block("Reference: INC-2026-0417")
        entities = engine.detect(block)
        # Should not be detected as any PII type
        for e in entities:
            assert e.value != "INC-2026-0417", (
                f"INC-2026-0417 should be allow-listed, but detected as {e.entity_type.value}"
            )

    def test_risk_reference(self, engine):
        block = _make_block("Risk ID: RSK-001")
        entities = engine.detect(block)
        for e in entities:
            assert "RSK-001" not in e.value

    def test_policy_reference(self, engine):
        block = _make_block("Policy: GRP-POL-001")
        entities = engine.detect(block)
        for e in entities:
            assert "GRP-POL-001" not in e.value

    def test_control_reference(self, engine):
        block = _make_block("Control: CTL-IAM-001")
        entities = engine.detect(block)
        for e in entities:
            assert "CTL-IAM-001" not in e.value


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_text(self, engine):
        block = _make_block("")
        entities = engine.detect(block)
        assert len(entities) == 0

    def test_whitespace_only(self, engine):
        block = _make_block("   \n\t  ")
        entities = engine.detect(block)
        assert len(entities) == 0

    def test_no_pii(self, engine):
        block = _make_block("This is a regular sentence without any sensitive data.")
        entities = engine.detect(block)
        assert len(entities) == 0

    def test_offset_tracking(self, engine):
        """Text offsets should match the actual value position."""
        text = "My SSN is 123-45-6789 and that's it."
        block = _make_block(text)
        entities = engine.detect(block)
        ssn_entities = [e for e in entities if e.entity_type == EntityType.SSN]
        if ssn_entities:
            entity = ssn_entities[0]
            assert text[entity.text_start:entity.text_end] == entity.value

    def test_batch_detection(self, engine):
        blocks = [
            _make_block("Email: test@test.com", block_id="b1", page=1),
            _make_block("SSN: 123-45-6789", block_id="b2", page=2),
        ]
        entities = engine.detect_batch(blocks)
        assert len(entities) >= 2

    def test_pattern_count(self, engine):
        """Engine should have multiple patterns loaded."""
        assert engine.get_pattern_count() > 20

    def test_entity_types_covered(self, engine):
        """Engine should cover multiple entity types."""
        types = engine.get_entity_types()
        assert len(types) >= 10
