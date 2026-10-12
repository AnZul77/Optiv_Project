"""
Unit tests for PII span detection in raw/OCR text (src.ocr.regions).
"""

import pytest
from src.ocr.regions import find_pii_spans_in_text


class TestEmptyAndInvalidInputs:
    """Test handling of None, empty strings, and non-string inputs."""

    def test_none_input(self):
        assert find_pii_spans_in_text(None) == []

    def test_empty_string(self):
        assert find_pii_spans_in_text("") == []

    def test_whitespace_only(self):
        assert find_pii_spans_in_text("   \t\n  ") == []

    def test_non_string_types(self):
        assert find_pii_spans_in_text(12345) == []
        assert find_pii_spans_in_text([]) == []
        assert find_pii_spans_in_text({}) == []
        assert find_pii_spans_in_text(3.14) == []


class TestPIICategories:
    """Test recognition across all individual PII categories."""

    def test_ssn_detection(self):
        text = "Employee SSN: 900-12-3456 on record"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        s, e = spans[0]
        assert text[s:e] == "900-12-3456"

    def test_email_standard(self):
        text = "Contact alice.walker@optiv-security.com for details"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        s, e = spans[0]
        assert text[s:e] == "alice.walker@optiv-security.com"

    def test_email_domain_specific(self):
        text = "Send report to contact@cadencefg.com today"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        s, e = spans[0]
        assert "contact@cadencefg.com" in text[s:e]

    def test_phone_numbers(self):
        text = "Call +1 (415) 555-2671 immediately"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        s, e = spans[0]
        assert "+1 (415) 555-2671" in text[s:e]

    def test_phone_exclusion_standards(self):
        # ISO 30410 or issue 155-2026-0066 should NOT match as phone numbers
        text = "ISO 30410 standard and ticket 155-2026-0066"
        spans = find_pii_spans_in_text(text)
        assert spans == []

    def test_employee_and_enterprise_ids(self):
        text = "Employee EMP-908234 and contractor MER-55412"
        spans = find_pii_spans_in_text(text)
        matched = [text[s:e] for s, e in spans]
        assert "EMP-908234" in matched
        assert "MER-55412" in matched

    def test_bare_5digit_id_and_iso_exclusions(self):
        # Bare 5-digit employee ID preceded by delimiter
        text = "Reviewer (84920) certified against ISO 27001 and ISO 31000"
        spans = find_pii_spans_in_text(text)
        matched = [text[s:e] for s, e in spans]
        assert "84920" in matched
        # Excluded standards should not be detected as employee IDs
        assert "27001" not in matched
        assert "31000" not in matched

    def test_target_names_and_case_insensitivity(self):
        # Miriam Achebe in uppercase
        text = "CONFIDENTIAL: ATTENDEE MIRIAM ACHEBE ATTENDED"
        spans = find_pii_spans_in_text(text)
        assert len(spans) >= 1
        matched_text = " ".join(text[s:e] for s, e in spans)
        assert "MIRIAM ACHEBE" in matched_text

    def test_individual_target_names(self):
        text = "Discussion with Tobias and Delphine regarding policy"
        spans = find_pii_spans_in_text(text)
        matched = [text[s:e] for s, e in spans]
        assert "Tobias" in matched
        assert "Delphine" in matched

    def test_abbreviated_names(self):
        text = "Approved by T. Lindqvist and M. Achebe"
        spans = find_pii_spans_in_text(text)
        matched = [text[s:e] for s, e in spans]
        assert any("T. Lindqvist" in m or "Lindqvist" in m for m in matched)
        assert any("M. Achebe" in m or "Achebe" in m for m in matched)

    def test_exact_addresses_and_phrases(self):
        text = "Office address: 245 Hudson Street, New York NY 10013."
        spans = find_pii_spans_in_text(text)
        assert len(spans) >= 1
        full_match = "".join(text[s:e] for s, e in spans)
        assert "245 Hudson Street" in full_match or "245 hudson street" in full_match.lower()

    def test_pan_and_passport(self):
        text = "Director PAN ABCDE1234F holding passport TK4820913"
        spans = find_pii_spans_in_text(text)
        matched = [text[s:e] for s, e in spans]
        assert any("ABCDE1234F" in m for m in matched)
        assert any("TK4820913" in m for m in matched)

    def test_date_of_birth(self):
        text = "Subject DOB: 11/04/1978 confirmed"
        spans = find_pii_spans_in_text(text)
        assert len(spans) >= 1
        matched = [text[s:e] for s, e in spans]
        assert any("11/04/1978" in m for m in matched)


class TestBoundaryAndMergeSemantics:
    """Test boundary conditions, offsets, and non-overlapping merge invariants."""

    def test_pii_at_string_start(self):
        text = "900-12-3456 is the SSN"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        assert spans[0][0] == 0
        assert text[spans[0][0]:spans[0][1]] == "900-12-3456"

    def test_pii_at_string_end(self):
        text = "The SSN is 900-12-3456"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        assert spans[0][1] == len(text)
        assert text[spans[0][0]:spans[0][1]] == "900-12-3456"

    def test_overlapping_spans_are_cleanly_merged(self):
        # "Anthony P. Brightwell" contains exact phrase "anthony p. brightwell",
        # "anthony brightwell", and target name "anthony", "brightwell".
        text = "Anthony P. Brightwell signed the document."
        spans = find_pii_spans_in_text(text)
        # All overlapping sub-matches must merge into one clean interval
        assert len(spans) == 1
        assert text[spans[0][0]:spans[0][1]] == "Anthony P. Brightwell"

    def test_multiple_entities_ordered_and_disjoint(self):
        text = "Miriam Achebe (EMP-10293) email: miriam@cadencefg.com phone: 555-019-2834"
        spans = find_pii_spans_in_text(text)
        assert len(spans) >= 3

        # Invariant checks: strictly sorted, non-overlapping, valid bounds
        for i in range(len(spans)):
            s, e = spans[i]
            assert 0 <= s < e <= len(text)
            if i > 0:
                prev_s, prev_e = spans[i - 1]
                assert s >= prev_e, f"Spans overlap: {spans[i-1]} and {spans[i]}"

    def test_clean_text_no_false_positives(self):
        text = "Enterprise Risk Governance Framework Version 4.2 section 12"
        spans = find_pii_spans_in_text(text)
        assert spans == []
