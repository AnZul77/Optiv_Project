"""
Unit tests for proportional font bounding box alignment, middle-initial bridging,
OCR degradation handling, and 5px safety margin padding.
Worker M1: Vision & Bounding Box Alignment Lead
"""

import inspect
import numpy as np
import pytest
from PIL import Image

from src.ocr.regions import (
    find_pii_spans_in_text,
    extract_word_level_pii_boxes,
)
from src.sanitization.pdf_redactor import redact_scanned_pdf
from src.sanitization.image_redactor import (
    redact_image,
    redact_image_bytes,
    burn_redactions_on_image,
)


class TestMiddleInitialAndPhraseBridging:
    """Tests for bridging first names, middle initials, and last names into continuous spans."""

    def test_devansh_r_kulkarni_bridged(self):
        text = "Devansh R. Kulkarni (EMP-39220)"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 2
        assert text[spans[0][0]:spans[0][1]] == "Devansh R. Kulkarni"
        assert text[spans[1][0]:spans[1][1]] == "EMP-39220"

    def test_rohan_s_deshmukh_bridged(self):
        text = "Risk Manager: Rohan S. Deshmukh"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        assert text[spans[0][0]:spans[0][1]] == "Rohan S. Deshmukh"

    def test_rafael_e_colon_duarte_bridged(self):
        # OCR degradation with colon after middle initial
        text = "Rafael E: Duarte (EMP-40944)"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 2
        assert text[spans[0][0]:spans[0][1]] == "Rafael E: Duarte"
        assert text[spans[1][0]:spans[1][1]] == "EMP-40944"

    def test_anthony_p_brightwell_bridged(self):
        text = "Board Chair: Anthony P. Brightwell"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        assert text[spans[0][0]:spans[0][1]] == "Anthony P. Brightwell"

    def test_rosalind_m_achterberg_bridged(self):
        text = "Approved by Rosalind M. Achterberg, CRO"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        assert text[spans[0][0]:spans[0][1]] == "Rosalind M. Achterberg"

    def test_desmond_n_quarshie_bridged(self):
        text = "Lead Auditor Desmond N. Quarshie confirmed"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        assert text[spans[0][0]:spans[0][1]] == "Desmond N. Quarshie"


class TestOCRDegradationVariants:
    """Tests for matching OCR error forms and degradation variants."""

    def test_emilic_cross_box_match(self):
        text = "(305) 555-0143 and that your husband, Emilic"
        spans = find_pii_spans_in_text(text)
        matched = [text[s:e] for s, e in spans]
        assert "(305) 555-0143" in matched
        assert "Emilic" in matched

    def test_briqhtwell_with_q(self):
        text = "Briqhtwell (DIR-0042)"
        spans = find_pii_spans_in_text(text)
        matched = [text[s:e] for s, e in spans]
        assert "Briqhtwell" in matched
        assert "DIR-0042" in matched

    def test_privanka_with_v(self):
        text = "Assigned to Privanka for follow-up"
        spans = find_pii_spans_in_text(text)
        matched = [text[s:e] for s, e in spans]
        assert "Privanka" in matched

    def test_valdvanathan_full_token(self):
        text = "Senior Analyst: Valdvanathan"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        # Entire word must be matched, not just the subspan 'vanathan'
        assert text[spans[0][0]:spans[0][1]] == "Valdvanathan"

    def test_page_34_tobias_degradations(self):
        for variant in ["TTobias Kinoovist", "Tobias Lindovist", "\"Tobias Lindqvist"]:
            spans = find_pii_spans_in_text(variant)
            assert len(spans) >= 1
            matched = " ".join(variant[s:e] for s, e in spans)
            assert "Tobias" in matched or "TTobias" in matched or "Lindovist" in matched or "Kinoovist" in matched


class TestSensitivePartialTokensAndBusinessAllowList:
    """Tests for 4-digit tokens and safe business identifier protection."""

    def test_standalone_4digit_account_tokens(self):
        for token in ["7741", "2218", "8827"]:
            spans = find_pii_spans_in_text(token)
            assert len(spans) == 1
            assert token[spans[0][0]:spans[0][1]] == token

    def test_partial_account_phrases(self):
        text = "Platinum card ending 2218 and savings account ending 7741"
        spans = find_pii_spans_in_text(text)
        assert len(spans) >= 2

    def test_preserve_safe_business_identifiers(self):
        # Allow-listed business codes must NEVER be redacted
        safe_texts = [
            "Document reference GRP-POL-001 approved",
            "Risk category code RSK-4488 active",
            "Access management rule CTL-IAM-004 verified",
            "Standard ISO 31000:2018 compliance",
        ]
        for st in safe_texts:
            spans = find_pii_spans_in_text(st)
            assert spans == [], f"Safe text was incorrectly matched: {st} -> {spans}"

    def test_preserve_table_headers(self):
        for header in ["Employee Name", "Employee ID", "Risk Code", "Control ID", "Policy Title", "Reviewer"]:
            spans = find_pii_spans_in_text(header)
            assert spans == [], f"Table header '{header}' was incorrectly flagged as PII"


class TestPhoneVariants:
    """Tests for international phone numbers including French 1-digit area codes."""

    def test_french_single_digit_area_code(self):
        text = "Paris office phone: +33 1 5555 0144"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        assert "+33 1 5555 0144" in text[spans[0][0]:spans[0][1]]

    def test_polish_phone_number(self):
        text = "Warsaw contact: +48 512 555 0180"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        assert "+48 512 555 0180" in text[spans[0][0]:spans[0][1]]


class TestProportionalBoundingBoxAlignment:
    """Tests for proportional font bounding box alignment in extract_word_level_pii_boxes."""

    def test_proportional_weighting_eliminates_left_drift(self):
        # "chaired by Priyanka S. Raghavan:" on a 200 DPI page (1700x2200)
        # Bbox in raw image: [206.0, 536.0, 534.0, 564.0]
        # In linear char interpolation, Priyanka starts too far to the right ("Pr [box]").
        # In proportional alignment, the box encloses Priyanka from the beginning of 'P'.
        line = "chaired by Priyanka S. Raghavan:"
        pts = [[206.0, 536.0], [534.0, 536.0], [534.0, 564.0], [206.0, 564.0]]
        boxes = extract_word_level_pii_boxes([(pts, line)], img_w=1700, img_h=2200)

        assert len(boxes) == 1
        b = boxes[0]
        # Bounding box left edge in pixels (b[0] * 1700) must cover Priyanka (x ~ 308-313 px)
        # Linear was 318.8 px, which cut off 'P' and 'r'.
        # With proportional font alignment and 5px padding, b[0] * 1700 should be <= 310 px.
        box_left_px = b[0] * 1700.0
        assert box_left_px <= 310.0, f"Box left edge ({box_left_px:.1f}px) cut off leading characters"

    def test_scale_invariant_padding_across_dpis(self):
        # Test that coordinate normalization cleanly scales between 120 DPI and 200 DPI
        line = "Tobias Lindqvist"
        pts_120 = [[100.0, 200.0], [300.0, 200.0], [300.0, 230.0], [100.0, 230.0]]
        boxes_120 = extract_word_level_pii_boxes([(pts_120, line)], img_w=1020, img_h=1320)

        assert len(boxes_120) == 1
        b120 = boxes_120[0]
        # Normalized padding margin (100 - x0_padded) / 1020
        pad_fraction = (100.0 / 1020.0) - b120[0]
        assert pad_fraction >= 5.0 / 1020.0 - 1e-5


class TestStandardizedFivePixelPadding:
    """Tests verifying 5px default padding across all sanitization functions."""

    def test_pdf_redactor_default_padding_is_5(self):
        sig = inspect.signature(redact_scanned_pdf)
        assert sig.parameters["padding"].default == 5

    def test_image_redactor_default_padding_is_5(self):
        for fn in [redact_image, redact_image_bytes, burn_redactions_on_image]:
            sig = inspect.signature(fn)
            assert sig.parameters["padding"].default == 5, f"{fn.__name__} default padding is not 5"

    def test_redact_image_expands_by_5_pixels(self):
        image = Image.new("RGB", (100, 100), "white")
        box = [0.4, 0.4, 0.6, 0.6]  # 40..60 px
        # Rely on default padding=5
        result = redact_image(image, [box])
        arr = np.array(result)
        # 5px padding extends box from 40..60 to 35..65
        assert np.all(arr[36, 50] == 0)
        assert np.all(arr[64, 50] == 0)
        assert np.all(arr[50, 36] == 0)
        assert np.all(arr[50, 64] == 0)
        # Pixels outside the 5px safety margin remain white
        assert np.all(arr[30, 50] == 255)
        assert np.all(arr[70, 50] == 255)
