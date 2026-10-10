"""
Unit Tests: PII Detection Core (Checklist Verification)
======================================================

Aggregates layer 1-4 detection unit verification against the Developer 3
Architecture Guide specifications:
- Regex Catalog (EMAIL, PHONE, SSN, PAN, AADHAAR, CARD, EMPLOYEE_ID)
- Presidio + spaCy NER
- Context token window cues and table header inheritance
- Checksum Validators (Luhn, Verhoeff, libphonenumbers)
"""

import pytest
from src.schema.entities import (
    ContentBlock,
    EntityType,
    TableContext,
    ValidatorStatus,
    EntityAnnotation,
)
from src.detection.regex import RegexEngine
from src.detection.context import ContextEngine
from src.detection.validators import ValidatorEngine


class TestDetectionChecklist:
    """Explicit tests matching Developer 3 Architecture Guide checklist."""

    def test_entity_annotation_alias(self):
        """Verify EntityAnnotation is an alias for PIIEntity."""
        from src.schema.entities import PIIEntity
        assert EntityAnnotation is PIIEntity

    def test_regex_deterministic_catalog(self):
        """Layer 1: Deterministic regex tests for all core types."""
        regex = RegexEngine()
        block = ContentBlock(
            text=(
                "Email: test.dev@cadence.com, Phone: (555) 234-5678, "
                "SSN: 123-45-6789, PAN: ABCPE1234F, Aadhaar: 2345 6789 0123, "
                "Card: 4532-1234-5678-9010, Employee: EMP-889900"
            ),
            block_id="b_regex",
            page=1,
        )
        entities = regex.detect(block)
        types = {e.entity_type for e in entities}

        assert EntityType.EMAIL in types
        assert EntityType.PHONE in types
        assert EntityType.SSN in types
        assert EntityType.PAN in types
        assert EntityType.AADHAAR in types
        assert EntityType.CARD in types
        assert EntityType.EMPLOYEE_ID in types

    def test_context_table_header_and_cues(self):
        """Layer 3: Table column header inheritance & cue boost."""
        context = ContextEngine(window_size=40)

        # 1. Table cell inheriting SSN from header
        cell_block = ContentBlock(
            text="123456789",
            block_id="cell_ssn",
            page=1,
            table_context=TableContext(
                header_name="SSN",
                row_index=1,
                col_index=1,
            ),
        )
        table_entities = context.detect(cell_block)
        assert any(e.entity_type == EntityType.SSN for e in table_entities)

        # 2. Cue boosting
        cue_block = ContentBlock(
            text="Employee DOB: 1990-05-15",
            block_id="cue_dob",
            page=1,
        )
        cue_entities = context.detect(cue_block)
        assert any(e.entity_type == EntityType.DOB for e in cue_entities)

    def test_validators_luhn_verhoeff_phone(self):
        """Layer 4: Luhn, Verhoeff, and phone validation."""
        validators = ValidatorEngine()

        # Luhn check
        card_pass = EntityAnnotation(
            entity_type=EntityType.CARD,
            value="4111111111111111",
            source="regex",
        )
        validators.validate(card_pass)
        assert card_pass.validator_result == ValidatorStatus.PASS

        card_fail = EntityAnnotation(
            entity_type=EntityType.CARD,
            value="4532015099991235",
            source="regex",
        )
        validators.validate(card_fail)
        assert card_fail.validator_result == ValidatorStatus.FAIL

        # Verhoeff check (Aadhaar starting with 0/1 fails)
        aadhaar_fail = EntityAnnotation(
            entity_type=EntityType.AADHAAR,
            value="012345678901",
            source="regex",
        )
        validators.validate(aadhaar_fail)
        assert aadhaar_fail.validator_result == ValidatorStatus.FAIL
