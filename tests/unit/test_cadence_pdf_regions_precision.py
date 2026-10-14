"""
Precision unit tests for Cadence PDF OCR regions, prefix label protections,
allow-list non-PII safeguards, and word-level box merging.
"""

import pytest
from src.ocr.regions import (
    find_pii_spans_in_text,
    extract_word_level_pii_boxes,
)


class TestPrefixLabelProtection:
    """Test that prefix labels like 'Author:', 'Lead:', etc. are never damaged."""

    def test_author_prefix_preserved(self):
        text = "Author: Anthony P. Brightwell"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        s, e = spans[0]
        # PII span must strictly start after 'Author: '
        assert text[:s] == "Author: "
        assert text[s:e] == "Anthony P. Brightwell"

        # Check calculated boxes
        boxes = extract_word_level_pii_boxes(
            [([ [100, 200], [500, 200], [500, 230], [100, 230] ], text, 0.99)],
            img_w=1000,
            img_h=1000,
            padding=0
        )
        assert len(boxes) == 1
        norm_x0 = boxes[0][0]
        # norm_x0 in pixels must be > 100 + (len("Author: ") / len(text)) * 400 * 0.7
        pixel_x0 = norm_x0 * 1000
        assert pixel_x0 > 150, f"Expected box to start after 'Author:', but got pixel_x0={pixel_x0}"

    def test_three_lines_lead_protection(self):
        text = "Lead: Sofia Marchetti-Lang (EMP-39044)"
        spans = find_pii_spans_in_text(text)
        assert len(spans) >= 1
        full_match = " ".join(text[s:e] for s, e in spans)
        assert "Sofia Marchetti-Lang" in full_match
        assert "EMP-39044" in full_match
        # 'Lead: ' must not be in any matched span
        for s, e in spans:
            assert "lead:" not in text[s:e].lower()


class TestEmailTrailingFragments:
    """Test that emails with OCR spaces before TLD or in parentheses are fully captured."""

    def test_spaced_tld_captured(self):
        text = "Contact ysorokina@cadencefg com for queries"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        s, e = spans[0]
        assert "ysorokina@cadencefg com" in text[s:e]

    def test_ocr_degraded_email_domain(self):
        text = "Inquiries to achebe@ cadencely cOm; immediately"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        s, e = spans[0]
        assert "achebe@ cadencely cOm" in text[s:e]

    def test_parenthesized_email(self):
        text = "Report owner (m.achebe@cadencefg.com) approved"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        s, e = spans[0]
        assert text[s:e] == "m.achebe@cadencefg.com"


class TestWhistleblowerAndFinancialProtection:
    """Test that whistleblower names and financial tokens are cleanly recognized."""

    def test_whistleblower_named_cases(self):
        text = "Case SPK-2026-0064 Raised by Named — T. Lindqvist"
        spans = find_pii_spans_in_text(text)
        assert len(spans) >= 1
        matched = [text[s:e] for s, e in spans]
        assert any("Named — T. Lindqvist" in m or "T. Lindqvist" in m for m in matched)

    def test_whistleblower_osadebe(self):
        text = "Theme: Concerns Raised: Named — N. K. Osadebe"
        spans = find_pii_spans_in_text(text)
        assert len(spans) >= 1
        matched = [text[s:e] for s, e in spans]
        assert any("Named — N. K. Osadebe" in m or "N. K. Osadebe" in m for m in matched)

    def test_savings_account_ending_7741(self):
        text = "linked savings account ending 7741 on file"
        spans = find_pii_spans_in_text(text)
        assert len(spans) >= 1
        matched = [text[s:e] for s, e in spans]
        assert any("7741" in m for m in matched)

    def test_card_ending_2218(self):
        text = "Cadence Platinum card ending 2218 was replaced"
        spans = find_pii_spans_in_text(text)
        assert len(spans) >= 1
        matched = [text[s:e] for s, e in spans]
        assert any("2218" in m for m in matched)


class TestAllowlistAndNonPIIProtections:
    """Test that legitimate business codes, tolerances, and labels are NEVER redacted."""

    def test_issue_reference_preserved(self):
        text = "Issue ISS-2026-0097 and extension ISS-2025-0431 (ext. 2)"
        spans = find_pii_spans_in_text(text)
        assert spans == [], f"Expected ISS numbers to be allow-listed, but got spans: {spans}"

    def test_tolerance_band_99_95_percent_preserved(self):
        text = "Availability tolerance band: 99.90% — 99.95% target"
        spans = find_pii_spans_in_text(text)
        assert spans == [], f"Expected tolerance percentages to be preserved, but got: {spans}"

    def test_financial_range_preserved(self):
        text = "Trading book VaR USD 14m — 18m band"
        spans = find_pii_spans_in_text(text)
        assert spans == []

    def test_three_lines_model_preserved(self):
        text = "Governance aligned with IIA Three Lines Model"
        spans = find_pii_spans_in_text(text)
        assert spans == []

    def test_body_conflict_sentence_preserved(self):
        text = "Where a subordinate document conflicts with this policy, the policy takes precedence."
        spans = find_pii_spans_in_text(text)
        assert spans == []


class TestLineLevelBoxMerging:
    """Test that horizontally adjacent word boxes merge into a single solid rectangle."""

    def test_adjacent_name_words_merged(self):
        # Line containing "Miriam T. Achebe"
        pts = [[100.0, 200.0], [500.0, 200.0], [500.0, 230.0], [100.0, 230.0]]
        text = "Miriam T. Achebe"
        boxes = extract_word_level_pii_boxes(
            [(pts, text, 0.99)],
            img_w=1000,
            img_h=1000,
            padding=0
        )
        # Should be merged into exactly 1 contiguous bounding box, NOT 3 separate staircase boxes
        assert len(boxes) == 1
        box = boxes[0]
        assert box[0] < box[2]
        assert box[1] < box[3]
