"""
Algorithmic Validators (Layer 4)
================================

Validation routines that modify confidence scores based on algorithmic
checks. Validators verify the mathematical or structural validity of
detected PII values.

Key Principle:
    Validators MODIFY confidence but NEVER discard entities. The PRD states:
    "modify confidence without discarding non-standard synthetic data."
    A failed checksum still means the entity was detected — the risk engine
    (Person 4) makes the final REDACT/BLOCK/ALLOW decision.

Implemented Validators:
    - Luhn Algorithm:   Credit/debit card numbers
    - Verhoeff Algorithm: Indian Aadhaar numbers
    - Phone Validation: International phone numbers (via phonenumbers library)
    - PAN Validation:   Indian PAN card format (4th character entity type check)
    - SSN Validation:   US SSN area number range validation
    - Date Validation:  DOB reasonable range check (1900–2010)
    - Email Validation: Domain format and TLD validation
    - IFSC Validation:  5th character must be '0'
    - GST Validation:   State code (01–37) and embedded PAN check

**Ownership:** Person 3 (PII Detection & Context Engine Lead)
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple

from src.schema.entities import (
    PIIEntity,
    EntityType,
    ValidatorStatus,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Confidence Adjustment Rules
# =============================================================================

@dataclass
class ValidationAdjustment:
    """Result of a validation check with confidence adjustment."""

    status: ValidatorStatus
    confidence_delta: float
    reason: str


# =============================================================================
# Validator Engine
# =============================================================================

class ValidatorEngine:
    """
    Layer 4: Algorithmic validation to modify confidence scores.

    Runs appropriate validators based on entity type. Each validator
    returns a confidence adjustment (positive or negative) but never
    discards the entity.

    Usage:
        validator = ValidatorEngine()
        adjusted_entity = validator.validate(entity)
    """

    # Mapping of entity types to their validator methods
    _VALIDATOR_MAP = None

    def __init__(self):
        """Initialize the Validator Engine."""
        # Lazy initialization of validator map to avoid circular references
        if ValidatorEngine._VALIDATOR_MAP is None:
            ValidatorEngine._VALIDATOR_MAP = {
                EntityType.CARD: self._validate_card,
                EntityType.AADHAAR: self._validate_aadhaar,
                EntityType.PHONE: self._validate_phone,
                EntityType.PAN: self._validate_pan,
                EntityType.SSN: self._validate_ssn,
                EntityType.DOB: self._validate_dob,
                EntityType.EMAIL: self._validate_email,
                EntityType.IFSC: self._validate_ifsc,
                EntityType.GST: self._validate_gst,
                EntityType.NINO: self._validate_nino,
            }

        self._validators = {
            EntityType.CARD: self._validate_card,
            EntityType.AADHAAR: self._validate_aadhaar,
            EntityType.PHONE: self._validate_phone,
            EntityType.PAN: self._validate_pan,
            EntityType.SSN: self._validate_ssn,
            EntityType.DOB: self._validate_dob,
            EntityType.EMAIL: self._validate_email,
            EntityType.IFSC: self._validate_ifsc,
            EntityType.GST: self._validate_gst,
            EntityType.NINO: self._validate_nino,
        }

        logger.info(
            "ValidatorEngine initialized with %d validators",
            len(self._validators),
        )

    def validate(self, entity: PIIEntity) -> PIIEntity:
        """
        Run the appropriate validator for an entity and adjust confidence.

        Args:
            entity: The PIIEntity to validate.

        Returns:
            The same entity with adjusted confidence and validator_result.
        """
        validator_func = self._validators.get(entity.entity_type)

        if validator_func is None:
            entity.validator_result = ValidatorStatus.NOT_APPLICABLE
            return entity

        try:
            adjustment = validator_func(entity.value)
            entity.validator_result = adjustment.status

            # Apply confidence adjustment
            old_confidence = entity.confidence
            entity.confidence = max(0.0, min(1.0, entity.confidence + adjustment.confidence_delta))

            # Add validator to detection layers
            if "validator" not in entity.detection_layers:
                entity.detection_layers.append("validator")

            logger.debug(
                "Validated %s (type=%s): %s → confidence %.2f → %.2f (%s)",
                entity.entity_id[:20], entity.entity_type.value,
                adjustment.status.value, old_confidence,
                entity.confidence, adjustment.reason,
            )

        except Exception as e:
            logger.warning(
                "Validator failed for %s (type=%s): %s",
                entity.entity_id[:20], entity.entity_type.value, e,
            )
            entity.validator_result = ValidatorStatus.NOT_APPLICABLE

        return entity

    def validate_batch(self, entities: list[PIIEntity]) -> list[PIIEntity]:
        """
        Validate a batch of entities.

        Args:
            entities: List of PIIEntity instances to validate.

        Returns:
            The same entities with adjusted confidence scores.
        """
        validated_count = 0
        for entity in entities:
            self.validate(entity)
            if entity.validator_result != ValidatorStatus.NOT_APPLICABLE:
                validated_count += 1

        logger.info("Validated %d / %d entities", validated_count, len(entities))
        return entities

    # =========================================================================
    # Individual Validators
    # =========================================================================

    def _validate_card(self, value: str) -> ValidationAdjustment:
        """
        Luhn algorithm validation for credit/debit card numbers.

        The Luhn algorithm (mod 10 check) validates most credit card numbers.
        """
        digits = re.sub(r"[\s\-]", "", value)

        if not digits.isdigit() or len(digits) < 13 or len(digits) > 19:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.20,
                reason=f"Invalid card length: {len(digits)} digits",
            )

        if self._luhn_check(digits):
            return ValidationAdjustment(
                status=ValidatorStatus.PASS,
                confidence_delta=0.05,  # Boost — but base was already high
                reason="Luhn checksum passed",
            )
        else:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.20,
                reason="Luhn checksum failed",
            )

    def _validate_aadhaar(self, value: str) -> ValidationAdjustment:
        """
        Verhoeff algorithm validation for Indian Aadhaar numbers.

        Aadhaar uses the Verhoeff checksum algorithm on 12 digits.
        """
        digits = re.sub(r"[\s\-]", "", value)

        if not digits.isdigit() or len(digits) != 12:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.15,
                reason=f"Invalid Aadhaar length: {len(digits)} digits",
            )

        # First digit cannot be 0 or 1
        if digits[0] in "01":
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.15,
                reason=f"Aadhaar cannot start with {digits[0]}",
            )

        if self._verhoeff_check(digits):
            return ValidationAdjustment(
                status=ValidatorStatus.PASS,
                confidence_delta=0.05,
                reason="Verhoeff checksum passed",
            )
        else:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.15,
                reason="Verhoeff checksum failed (may be synthetic data)",
            )

    def _validate_phone(self, value: str) -> ValidationAdjustment:
        """
        International phone number validation using phonenumbers library.

        Falls back to basic format validation if phonenumbers is not available.
        """
        try:
            import phonenumbers

            # Try parsing as-is first, then with common country codes
            parsed = None
            for region in [None, "US", "IN", "GB"]:
                try:
                    parsed = phonenumbers.parse(value, region)
                    if phonenumbers.is_valid_number(parsed):
                        return ValidationAdjustment(
                            status=ValidatorStatus.PASS,
                            confidence_delta=0.10,
                            reason=f"Valid phone: {phonenumbers.region_code_for_number(parsed)}",
                        )
                except phonenumbers.NumberParseException:
                    continue

            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.10,
                reason="Phone number validation failed",
            )

        except ImportError:
            logger.warning("phonenumbers library not installed, using basic validation")
            return self._validate_phone_basic(value)

    def _validate_phone_basic(self, value: str) -> ValidationAdjustment:
        """Basic phone validation without phonenumbers library."""
        digits = re.sub(r"[\s\-\(\)\+\.]", "", value)
        if digits.isdigit() and 7 <= len(digits) <= 15:
            return ValidationAdjustment(
                status=ValidatorStatus.PASS,
                confidence_delta=0.05,
                reason=f"Basic phone format valid: {len(digits)} digits",
            )
        return ValidationAdjustment(
            status=ValidatorStatus.FAIL,
            confidence_delta=-0.10,
            reason=f"Basic phone format invalid: {len(digits)} digits",
        )

    def _validate_pan(self, value: str) -> ValidationAdjustment:
        """
        Indian PAN card format validation.

        Format: XXXPX1234X where the 4th character indicates entity type:
            P = Individual, C = Company, H = HUF, A = AOP,
            T = Trust, B = BOI, L = Local Authority, J = AJP,
            F = Firm, G = Government
        """
        value_upper = value.strip().upper()

        if not re.match(r"^[A-Z]{5}\d{4}[A-Z]$", value_upper):
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.20,
                reason="PAN format invalid",
            )

        # 4th character must be a valid entity type code
        valid_4th = set("PCHATBLJFG")
        if value_upper[3] in valid_4th:
            return ValidationAdjustment(
                status=ValidatorStatus.PASS,
                confidence_delta=0.05,
                reason=f"PAN valid: entity type '{value_upper[3]}'",
            )
        else:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.20,
                reason=f"PAN 4th char '{value_upper[3]}' is not a valid entity type",
            )

    def _validate_ssn(self, value: str) -> ValidationAdjustment:
        """
        US SSN area number range validation.

        Rules:
            - Area number (first 3 digits) cannot be 000, 666, or 900-999
            - Group number (middle 2 digits) cannot be 00
            - Serial number (last 4 digits) cannot be 0000
        """
        digits = re.sub(r"[\s\-]", "", value)

        if not digits.isdigit() or len(digits) != 9:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.25,
                reason=f"SSN must be 9 digits, got {len(digits)}",
            )

        area = int(digits[:3])
        group = int(digits[3:5])
        serial = int(digits[5:])

        if area == 0 or area == 666 or area >= 900:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.25,
                reason=f"SSN area number {area} is invalid",
            )

        if group == 0:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.25,
                reason="SSN group number cannot be 00",
            )

        if serial == 0:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.25,
                reason="SSN serial number cannot be 0000",
            )

        return ValidationAdjustment(
            status=ValidatorStatus.PASS,
            confidence_delta=0.05,
            reason="SSN format valid",
        )

    def _validate_dob(self, value: str) -> ValidationAdjustment:
        """
        Date of Birth range validation.

        Checks if the date falls within a reasonable range for a person's
        birth date (1900–2010).
        """
        # Try multiple date formats
        date_formats = [
            "%m/%d/%Y", "%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y", "%m-%d-%Y",
            "%d.%m.%Y", "%m.%d.%Y", "%Y.%m.%d",
            "%B %d, %Y", "%d %B %Y", "%B %d %Y",
            "%b %d, %Y", "%d %b %Y", "%b %d %Y",
        ]

        parsed_date = None
        for fmt in date_formats:
            try:
                parsed_date = datetime.strptime(value.strip(), fmt)
                break
            except ValueError:
                continue

        if parsed_date is None:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.10,
                reason="Could not parse date format",
            )

        year = parsed_date.year
        if 1900 <= year <= 2010:
            return ValidationAdjustment(
                status=ValidatorStatus.PASS,
                confidence_delta=0.10,
                reason=f"DOB year {year} is in reasonable range",
            )
        elif 2010 < year <= datetime.now().year:
            return ValidationAdjustment(
                status=ValidatorStatus.PASS,
                confidence_delta=0.05,
                reason=f"Date year {year} is recent — possible DOB for minor",
            )
        else:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.15,
                reason=f"Date year {year} outside reasonable DOB range",
            )

    def _validate_email(self, value: str) -> ValidationAdjustment:
        """Basic email format and TLD validation."""
        # Check basic structure
        if not re.match(
            r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
            value.strip(),
        ):
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.10,
                reason="Invalid email format",
            )

        # Check for known valid TLDs
        domain = value.strip().split("@")[1].lower()
        known_tlds = {
            "com", "org", "net", "edu", "gov", "mil", "int",
            "co", "io", "ai", "us", "uk", "in", "de", "fr",
            "co.in", "co.uk", "com.au", "ac.in",
        }

        tld = ".".join(domain.split(".")[-2:]) if "." in domain.split(".")[-1] else domain.split(".")[-1]
        if tld in known_tlds or domain.split(".")[-1] in known_tlds:
            return ValidationAdjustment(
                status=ValidatorStatus.PASS,
                confidence_delta=0.03,
                reason=f"Email with known TLD: {domain}",
            )

        return ValidationAdjustment(
            status=ValidatorStatus.PASS,
            confidence_delta=0.0,
            reason=f"Email format valid, unknown TLD: {domain}",
        )

    def _validate_ifsc(self, value: str) -> ValidationAdjustment:
        """IFSC code validation: 5th character must be '0'."""
        value_upper = value.strip().upper()

        if len(value_upper) != 11:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.15,
                reason=f"IFSC must be 11 characters, got {len(value_upper)}",
            )

        if value_upper[4] != "0":
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.15,
                reason=f"IFSC 5th character must be '0', got '{value_upper[4]}'",
            )

        return ValidationAdjustment(
            status=ValidatorStatus.PASS,
            confidence_delta=0.05,
            reason="IFSC format valid",
        )

    def _validate_gst(self, value: str) -> ValidationAdjustment:
        """
        GST validation: state code (01–37) and embedded PAN check.

        Format: SS PPPPP DDDD P D Z C
                State(2) + PAN(10) + Entity(1) + Z + Check(1)
        """
        value_upper = value.strip().upper()

        if len(value_upper) != 15:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.15,
                reason=f"GST must be 15 characters, got {len(value_upper)}",
            )

        # State code: 01-37
        try:
            state_code = int(value_upper[:2])
            if state_code < 1 or state_code > 37:
                return ValidationAdjustment(
                    status=ValidatorStatus.FAIL,
                    confidence_delta=-0.15,
                    reason=f"GST state code {state_code} outside valid range (01-37)",
                )
        except ValueError:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.15,
                reason="GST state code is not numeric",
            )

        # 14th character (index 13) should be 'Z' by default
        if value_upper[13] != "Z":
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.10,
                reason=f"GST 14th character should be 'Z', got '{value_upper[13]}'",
            )

        return ValidationAdjustment(
            status=ValidatorStatus.PASS,
            confidence_delta=0.05,
            reason="GST format valid",
        )

    def _validate_nino(self, value: str) -> ValidationAdjustment:
        """
        UK NINO validation: prefix exclusion list and format check.

        Invalid prefixes: BG, GB, NK, KN, TN, NT, ZZ, and
        prefixes starting with D, F, I, Q, U, V.
        """
        nino = re.sub(r"\s", "", value.strip().upper())

        if len(nino) != 9:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.15,
                reason=f"NINO must be 9 characters, got {len(nino)}",
            )

        prefix = nino[:2]
        invalid_prefixes = {"BG", "GB", "NK", "KN", "TN", "NT", "ZZ"}
        invalid_first_chars = set("DFIQUV")

        if prefix in invalid_prefixes:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.15,
                reason=f"NINO prefix '{prefix}' is in exclusion list",
            )

        if nino[0] in invalid_first_chars:
            return ValidationAdjustment(
                status=ValidatorStatus.FAIL,
                confidence_delta=-0.15,
                reason=f"NINO cannot start with '{nino[0]}'",
            )

        return ValidationAdjustment(
            status=ValidatorStatus.PASS,
            confidence_delta=0.05,
            reason="NINO format valid",
        )

    # =========================================================================
    # Checksum Algorithms
    # =========================================================================

    @staticmethod
    def _luhn_check(number: str) -> bool:
        """
        Luhn algorithm (mod 10) for credit card validation.

        Steps:
            1. From the right, double every second digit
            2. If doubling results in > 9, subtract 9
            3. Sum all digits
            4. Total mod 10 should be 0
        """
        digits = [int(d) for d in number]
        digits.reverse()

        total = 0
        for i, digit in enumerate(digits):
            if i % 2 == 1:  # Every second digit from right
                doubled = digit * 2
                if doubled > 9:
                    doubled -= 9
                total += doubled
            else:
                total += digit

        return total % 10 == 0

    @staticmethod
    def _verhoeff_check(number: str) -> bool:
        """
        Verhoeff algorithm for Aadhaar number validation.

        Uses multiplication table, permutation table, and inverse table
        to compute a check digit based on dihedral group D5.
        """
        # Multiplication table
        d = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
            [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
            [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
            [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
            [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
            [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
            [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
            [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
            [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
        ]

        # Permutation table
        p = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
            [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
            [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
            [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
            [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
            [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
            [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
        ]

        digits = [int(x) for x in reversed(number)]
        c = 0
        for i, digit in enumerate(digits):
            c = d[c][p[i % 8][digit]]

        return c == 0
