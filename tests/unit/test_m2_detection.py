"""
Unit Tests for Milestone 2: PII Detection & Entity Resolution Engine
====================================================================

Tests cover:
1. Synthetic SSN 900-series detection in RegexEngine.
2. Polish PESEL, Cadence PAN cards, and international Passports.
3. Partial financial & sensitive tokens (card ending, account ending, SSN last 4 digits).
4. International phone formats (PL +48, FR +33, UK +44, US +1) and country code preservation in EntityResolver.
5. Algorithmic phone validation for PL/FR and fictitious test number handling.
6. Non-Anglo personnel name coverage in NEREngine without spaCy dropouts.
7. Safe business code allow-list and table header protection.
"""

import pytest
from src.schema.entities import (
    EntityType,
    ContentBlock,
    DetectionSource,
    PIIEntity,
    ValidatorStatus,
)
from src.detection.regex import RegexEngine
from src.detection.ner import NEREngine
from src.detection.validators import ValidatorEngine
from src.detection.resolver import EntityResolver
from src.detection.context import ContextEngine


def _make_block(text: str, block_id: str = "b-test", page: int = 1) -> ContentBlock:
    return ContentBlock(block_id=block_id, text=text, page=page, source_type="native_text")


# =============================================================================
# 1. Synthetic SSN 900-Series Tests
# =============================================================================

class TestSyntheticSSNDetection:
    """Verify synthetic SSN 900-series numbers are matched."""

    @pytest.fixture
    def engine(self):
        return RegexEngine()

    def test_synthetic_ssn_page_22_samples(self, engine):
        """Page 22 Risk Policy SSNs: 900-55-2043 and 900-42-7781."""
        block = _make_block("Target individual SSN: 900-55-2043 and co-borrower SSN 900-42-7781.")
        entities = engine.detect(block)
        ssns = [e for e in entities if e.entity_type == EntityType.SSN]
        assert len(ssns) == 2
        values = {e.value for e in ssns}
        assert "900-55-2043" in values
        assert "900-42-7781" in values
        for e in ssns:
            assert e.confidence >= 0.85

    def test_synthetic_ssn_with_spaces(self, engine):
        block = _make_block("SSN on record: 900 55 2043")
        entities = engine.detect(block)
        ssns = [e for e in entities if e.entity_type == EntityType.SSN]
        assert len(ssns) == 1
        assert ssns[0].value == "900 55 2043"

    def test_invalid_ssn_000_and_666_still_rejected(self, engine):
        """Invalid area numbers 000 and 666 should still not match standard SSN."""
        block = _make_block("Invalid SSNs: 000-12-3456 and 666-12-3456")
        entities = engine.detect(block)
        ssns = [e for e in entities if e.entity_type == EntityType.SSN]
        assert len(ssns) == 0


# =============================================================================
# 2. Polish PESEL & National IDs Tests
# =============================================================================

class TestPolishPESELAndNationalIDs:
    """Verify Polish PESEL, Indian PAN cards, and Passports."""

    @pytest.fixture
    def engine(self):
        return RegexEngine()

    def test_polish_pesel_synthetic_masked(self, engine):
        """Page 25 sample: 890412xxxxx."""
        block = _make_block("National identification: PESEL 890412xxxxx registered in Warsaw.")
        entities = engine.detect(block)
        pesels = [e for e in entities if e.entity_type == EntityType.PESEL]
        assert len(pesels) >= 1
        assert any("890412xxxxx" in e.value for e in pesels)

    def test_polish_pesel_11_digits(self, engine):
        block = _make_block("PESEL: 89041212345")
        entities = engine.detect(block)
        pesels = [e for e in entities if e.entity_type == EntityType.PESEL]
        assert len(pesels) >= 1
        assert any("89041212345" in e.value for e in pesels)

    def test_cadence_pan_cards(self, engine):
        """Test PAN numbers from Cadence Risk Policy."""
        text = "Individual PAN: AQBPR7741L, director PAN CDRPK6612M, and signatory PAN BKTPV2290H."
        block = _make_block(text)
        entities = engine.detect(block)
        pans = [e for e in entities if e.entity_type == EntityType.PAN]
        assert len(pans) >= 3
        pan_vals = {e.value for e in pans}
        assert "AQBPR7741L" in pan_vals
        assert "CDRPK6612M" in pan_vals
        assert "BKTPV2290H" in pan_vals

    def test_cadence_passports(self, engine):
        """Test passports from Cadence Risk Policy."""
        text = "Passports verified: UK passport TK4820913 and US passport C8839201."
        block = _make_block(text)
        entities = engine.detect(block)
        passports = [e for e in entities if e.entity_type == EntityType.PASSPORT]
        assert len(passports) >= 2
        vals = {e.value for e in passports}
        assert "TK4820913" in vals
        assert "C8839201" in vals


# =============================================================================
# 3. Partial Financial & Identity Tokens Tests
# =============================================================================

class TestPartialFinancialAndIdentityTokens:
    """Verify partial tokens (card ending, account ending, SSN last 4)."""

    @pytest.fixture
    def engine(self):
        return RegexEngine()

    def test_card_ending_token(self, engine):
        block = _make_block("Corporate credit card ending 2218 was charged for security audit.")
        entities = engine.detect(block)
        cards = [e for e in entities if e.entity_type == EntityType.CARD]
        assert len(cards) >= 1
        assert any("2218" in e.value for e in cards)

    def test_savings_account_ending_token(self, engine):
        block = _make_block("Disbursement sent to savings account ending 7741.")
        entities = engine.detect(block)
        accounts = [e for e in entities if e.entity_type == EntityType.BANK_ACCOUNT]
        assert len(accounts) >= 1
        assert any("7741" in e.value for e in accounts)

    def test_account_ending_token(self, engine):
        block = _make_block("Wire transferred to account ending 7741.")
        entities = engine.detect(block)
        accounts = [e for e in entities if e.entity_type == EntityType.BANK_ACCOUNT]
        assert len(accounts) >= 1
        assert any("7741" in e.value for e in accounts)

    def test_ssn_last_4_digits_token(self, engine):
        block = _make_block("Identity verified via SSN last 4 digits (8827).")
        entities = engine.detect(block)
        ssns = [e for e in entities if e.entity_type == EntityType.SSN]
        assert len(ssns) >= 1
        assert any("8827" in e.value for e in ssns)


# =============================================================================
# 4. International Phone Formats & Validator Tests
# =============================================================================

class TestInternationalPhoneFormats:
    """Verify international phone numbers and validation in PL and FR."""

    @pytest.fixture
    def regex_engine(self):
        return RegexEngine()

    @pytest.fixture
    def validator(self):
        return ValidatorEngine()

    def test_polish_phone_detection_and_validation(self, regex_engine, validator):
        block = _make_block("Warsaw branch contact: +48 512 555 0180.")
        entities = regex_engine.detect(block)
        phones = [e for e in entities if e.entity_type == EntityType.PHONE]
        assert len(phones) >= 1
        full_phone = next(e for e in phones if "+48" in e.value)
        assert full_phone.value == "+48 512 555 0180"

        # Validate with ValidatorEngine — must NOT be penalized
        validator.validate(full_phone)
        assert full_phone.validator_result == ValidatorStatus.PASS
        assert full_phone.confidence >= 0.85

    def test_french_phone_detection_and_validation(self, regex_engine, validator):
        block = _make_block("Paris office direct line: +33 1 5555 0144.")
        entities = regex_engine.detect(block)
        phones = [e for e in entities if e.entity_type == EntityType.PHONE]
        assert len(phones) >= 1
        full_phone = next(e for e in phones if "+33" in e.value)
        assert "+33 1 5555 0144" in full_phone.value

        validator.validate(full_phone)
        assert full_phone.validator_result == ValidatorStatus.PASS

    def test_uk_phone_detection(self, regex_engine):
        block = _make_block("London headquarters: +44 20 7555 0171.")
        entities = regex_engine.detect(block)
        phones = [e for e in entities if e.entity_type == EntityType.PHONE]
        assert len(phones) >= 1
        assert any("+44" in e.value for e in phones)

    def test_us_phone_detection(self, regex_engine):
        block = _make_block("New York desk: +1 (212) 555-0108.")
        entities = regex_engine.detect(block)
        phones = [e for e in entities if e.entity_type == EntityType.PHONE]
        assert len(phones) >= 1
        assert any("212" in e.value for e in phones)


# =============================================================================
# 5. Entity Resolver: Phone Country Code Preservation
# =============================================================================

class TestPhoneCountryCodePreservation:
    """Verify that merging overlapping phone spans preserves the '+' country code."""

    @pytest.fixture
    def resolver(self):
        return EntityResolver()

    def test_preserve_plus_48_over_shorter_us_substring(self, resolver):
        """Simulate primary detection finding full '+48 512 555 0180' and sub-span '512 555 0180'."""
        text = "Contact: +48 512 555 0180"
        # Full phone entity
        e_full = PIIEntity(
            entity_type=EntityType.PHONE,
            value="+48 512 555 0180",
            source=DetectionSource.REGEX,
            confidence=0.88,
            text_start=9,
            text_end=25,
            block_id="b1",
        )
        # Shorter sub-span with artificially higher validator score
        e_sub = PIIEntity(
            entity_type=EntityType.PHONE,
            value="512 555 0180",
            source=DetectionSource.REGEX,
            confidence=0.98,
            text_start=13,
            text_end=25,
            block_id="b1",
        )

        resolved = resolver.resolve([e_full, e_sub])
        assert len(resolved) == 1
        res = resolved[0]
        # Must keep '+' prefix and start at 9
        assert res.text_start == 9
        assert res.value == "+48 512 555 0180"
        assert res.confidence == 0.98  # retains max confidence


# =============================================================================
# 6. Non-Anglo Personnel Name Coverage in NEREngine
# =============================================================================

class TestNonAngloPersonnelNameCoverage:
    """Verify NEREngine detects diverse Cadence executive & personnel names."""

    @pytest.fixture
    def ner(self):
        engine = NEREngine(score_threshold=0.35)
        engine.initialize()
        return engine

    @pytest.mark.parametrize("name", [
        "Rohan S. Deshmukh",
        "Lars-Erik Brannstrom",
        "Devansh R. Kulkarni",
        "Ananya V. Chatterjee",
        "Anthony P. Brightwell",
        "Tobias Lindqvist",
        "Rosalind M. Achterberg",
        "Desmond N. Quarshie",
        "Mireille Dubois-Kane",
        "Aiko Nakamura-Reed",
        "Hiroshi Yamagata",
        "Babatunde Osei-Tutu",
        "Ifeoma Adeyemi",
        "Adaeze Onwuka",
    ])
    def test_non_anglo_personnel_name_detected(self, ner, name):
        text = f"Report approved and signed off by {name} as designated authority."
        block = _make_block(text)
        entities = ner.detect(block)
        person_entities = [e for e in entities if e.entity_type == EntityType.PERSON]
        assert len(person_entities) >= 1, f"Failed to detect PERSON entity for '{name}'"
        assert any(name.lower() in e.value.lower() or e.value.lower() in name.lower() for e in person_entities)


# =============================================================================
# 7. Safe Business Context Allow-List & Table Header Protection
# =============================================================================

class TestBusinessContextAllowList:
    """Verify allow-listed business codes and table headers are never flagged as PII."""

    @pytest.fixture
    def regex_engine(self):
        return RegexEngine()

    @pytest.fixture
    def resolver(self):
        return EntityResolver()

    @pytest.mark.parametrize("code", [
        "GRP-POL-001",
        "RSK-4488",
        "CTL-IAM-01",
        "INC-2026-0417",
        "ISO 27001",
    ])
    def test_allow_listed_codes_not_extracted_as_pii(self, regex_engine, resolver, code):
        text = f"Policy document {code} details the mandatory risk appetite framework."
        block = _make_block(text)
        entities = regex_engine.detect(block)
        resolved = resolver.resolve(entities)
        for e in resolved:
            assert code not in e.value

    @pytest.mark.parametrize("header", [
        "Employee Name",
        "Employee ID",
        "Risk Code",
        "Control ID",
        "Policy Title",
        "Reviewer",
        "Status",
    ])
    def test_table_headers_never_become_pii_entities(self, regex_engine, header):
        block = _make_block(header)
        entities = regex_engine.detect(block)
        assert len(entities) == 0
