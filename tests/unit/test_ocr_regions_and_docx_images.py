"""
Unit tests for OCR Region Span Finder and DOCX Embedded Image Redaction.
Person 2: Vision & Multimodal Lead
"""

import io
import os
import pytest
import numpy as np
from PIL import Image, ImageDraw
from docx import Document

from src.ocr.regions import (
    find_pii_spans_in_text,
    extract_word_level_pii_boxes,
)
from src.sanitization.image_redactor import (
    burn_redactions_on_image,
    redact_image_pixels,
    redact_image,
    redact_image_bytes,
)
from src.sanitization.docx_reconstructor import DOCXReconstructor
from src.security.integrity import DocumentIntegrityGuard


class TestFindPIISpansInText:
    """Tests for core OCR span finder."""

    def test_empty_and_invalid_input(self):
        assert find_pii_spans_in_text("") == []
        assert find_pii_spans_in_text(None) == []
        assert find_pii_spans_in_text("Just an ordinary safe policy statement.") == []

    def test_names_and_exact_phrases(self):
        text = "Contact Sarah Jenkins at 245 Hudson Street, New York NY 10013 immediately."
        spans = find_pii_spans_in_text(text)
        assert len(spans) >= 2
        matched_texts = [text[s:e].lower() for s, e in spans]
        assert any("jenkins" in m or "sarah" in m for m in matched_texts)
        assert any("245 hudson street" in m for m in matched_texts)

    def test_employee_and_enterprise_ids(self):
        text = "Auditor EMP-89412 submitted review for DIR-3301 and MER-9012."
        spans = find_pii_spans_in_text(text)
        matched_texts = [text[s:e] for s, e in spans]
        assert "EMP-89412" in matched_texts
        assert "DIR-3301" in matched_texts
        assert "MER-9012" in matched_texts

    def test_emails_and_phones(self):
        text = "Reach out to user@optiv.com or call +1 (555) 234-5678 today."
        spans = find_pii_spans_in_text(text)
        matched_texts = [text[s:e] for s, e in spans]
        assert any("user@optiv.com" in m for m in matched_texts)
        assert any("555" in m and "234" in m for m in matched_texts)

    def test_ssn_and_national_ids(self):
        text = "Personal records: SSN 900-12-3456, PAN ABCDE1234F, Passport TK4820913."
        spans = find_pii_spans_in_text(text)
        matched_texts = [text[s:e] for s, e in spans]
        assert any("900-12-3456" in m for m in matched_texts)
        assert any("ABCDE1234F" in m for m in matched_texts)
        assert any("TK4820913" in m for m in matched_texts)

    def test_merges_overlapping_spans(self):
        # Anthony P. Brightwell contains Anthony and Brightwell
        text = "Sign-off: Anthony P. Brightwell"
        spans = find_pii_spans_in_text(text)
        # Should be merged or clean intervals without overlapping starts
        for i in range(len(spans) - 1):
            assert spans[i][1] <= spans[i + 1][0]


class TestExtractWordLevelPIIBoxes:
    """Tests for word-level bounding box calculations from OCR detections."""

    def test_invalid_dimensions(self):
        with pytest.raises(ValueError):
            extract_word_level_pii_boxes([], 0, 100)
        with pytest.raises(ValueError):
            extract_word_level_pii_boxes([], 100, -10)

    def test_easyocr_tuple_format(self):
        # Format: (4_points_polygon, text_line, score)
        pts = [[10.0, 20.0], [210.0, 20.0], [210.0, 40.0], [10.0, 40.0]]
        line = "Reviewer: Tobias Lindqvist (Approved)"
        results = [(pts, line, 0.95)]

        boxes = extract_word_level_pii_boxes(results, img_w=1000, img_h=500)
        assert len(boxes) >= 1
        # Each box should be normalized [x0, y0, x1, y1] within [0.0, 1.0]
        for b in boxes:
            assert len(b) == 4
            assert 0.0 <= b[0] <= b[2] <= 1.0
            assert 0.0 <= b[1] <= b[3] <= 1.0

    def test_dict_region_format(self):
        # Format like OCREngine extract output
        ocr_result = {
            "regions": [
                {
                    "word": "Officer Sarah Jenkins",
                    "pixel_bbox": [50.0, 100.0, 250.0, 130.0],
                    "confidence": 0.99,
                },
                {
                    "word": "Operational Risk Assessment",
                    "pixel_bbox": [50.0, 200.0, 300.0, 230.0],
                    "confidence": 0.99,
                }
            ]
        }
        boxes = extract_word_level_pii_boxes(ocr_result, img_w=1000, img_h=1000)
        assert len(boxes) >= 1

    def test_empty_results_returns_empty(self):
        boxes = extract_word_level_pii_boxes([], 500, 500)
        assert boxes == []


class TestImageRedactorFunctions:
    """Tests for burn_redactions_on_image and redact_image_pixels."""

    def test_burn_redactions_on_pil_image(self):
        img = Image.new("RGB", (200, 200), color="white")
        box = [0.25, 0.25, 0.75, 0.75]
        redacted = burn_redactions_on_image(img, [box], padding=0)
        assert isinstance(redacted, Image.Image)

        arr = np.array(redacted)
        # Inside box should be solid black (0, 0, 0)
        assert np.all(arr[60:140, 60:140] == 0)
        # Outside box should remain white (255, 255, 255)
        assert np.all(arr[10:30, 10:30] == 255)

    def test_burn_redactions_on_bytes(self):
        img = Image.new("RGB", (100, 100), color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        raw_bytes = buf.getvalue()

        box = [0.1, 0.1, 0.5, 0.5]
        redacted_bytes = burn_redactions_on_image(raw_bytes, [box], padding=2)
        assert isinstance(redacted_bytes, bytes)
        assert len(redacted_bytes) > 0

        # Verify pixel content of redacted bytes
        redacted_img = Image.open(io.BytesIO(redacted_bytes))
        arr = np.array(redacted_img)
        assert np.all(arr[20:40, 20:40] == 0)

    def test_alias_redact_image_pixels(self):
        assert redact_image_pixels is burn_redactions_on_image


class TestDOCXEmbeddedScreenshotRedaction:
    """Tests for end-to-end DOCX embedded screenshot OCR and pixel burning."""

    def test_docx_image_redaction_end_to_end(self, tmp_path):
        docx_in = tmp_path / "test_screenshot.docx"
        docx_out = tmp_path / "sanitized_screenshot.docx"

        # Create a test DOCX containing an embedded image
        doc = Document()
        doc.add_heading("Third-Party Vendor Assessment", level=1)
        doc.add_paragraph("Screenshot of OneTrust vendor portal:")

        # Create test screenshot with text "Approver: Sarah Jenkins"
        img = Image.new("RGB", (400, 100), color="white")
        draw = ImageDraw.Draw(img)
        draw.text((20, 40), "Approver: Sarah Jenkins", fill="black")

        img_buf = io.BytesIO()
        img.save(img_buf, format="PNG")
        img_bytes = img_buf.getvalue()

        doc.add_picture(io.BytesIO(img_bytes))
        doc.save(str(docx_in))

        # Mock OCR cache or detections for the test image
        ocr_cache = {
            "image1.png": [
                ([20, 30, 300, 70], "Approver: Sarah Jenkins")
            ]
        }

        # 1. Inspect embedded images and generate redacted pixel replacements
        replacements = DOCXReconstructor.redact_embedded_images(
            str(docx_in),
            ocr_cache=ocr_cache
        )
        assert len(replacements) > 0

        # 2. Re-inject redacted image bytes into DOCX
        success, err = DOCXReconstructor.replace_images_in_document(
            str(docx_in),
            str(docx_out),
            replacements
        )
        assert success is True
        assert err is None
        assert os.path.exists(str(docx_out))

        # 3. Verify integrity of output document
        check = DocumentIntegrityGuard.verify_document(str(docx_out))
        assert check.is_valid is True

        # 4. Verify that the image in the reconstructed DOCX now has burned pixels
        recon_doc = Document(str(docx_out))
        recon_img_rel = [
            rel for rel in recon_doc.part.rels.values()
            if "image" in getattr(rel, "target_ref", "").lower()
        ][0]
        recon_bytes = recon_img_rel.target_part.blob
        recon_pil = Image.open(io.BytesIO(recon_bytes))
        recon_arr = np.array(recon_pil)

        # Region where Sarah Jenkins was located must be burned black
        # Jenkins is in right half of [20..300], so x around 150..220, y around 35..65
        assert np.all(recon_arr[35:60, 150:200] == 0)
