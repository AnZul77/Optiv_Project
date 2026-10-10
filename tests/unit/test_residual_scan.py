"""
Unit Tests: Re-OCR Residual Scanner (Person 4)
==============================================

Uses canned OCR dicts in the exact shapes produced by Person 2's
OCREngine.extract() and src.ocr.residual_scan.scan_residual(), so no OCR
engine is needed.
"""

import pytest

from src.verification.residual_scan import ResidualScanner, evaluate_residual, overlap_fraction

BURNED = [[0.40, 0.40, 0.60, 0.45]]


def _engine_result(words, confidence=0.95, unmapped=None):
    return {
        "text": "\n".join(w["word"] for w in words) + ("\n" + "\n".join(unmapped) if unmapped else ""),
        "confidence": confidence,
        "words": words,
        "low_confidence": confidence <= 0.60,
        "unmapped_text": unmapped or [],
        "page": 1,
    }


def _residual(words, confidence=0.95, unmapped=None):
    raw = _engine_result(words, confidence, unmapped)
    return {
        "page": 1,
        "residual_text_found": bool(raw["text"].strip()),
        "residual_text": raw["text"],
        "confidence": confidence,
        "low_confidence": raw["low_confidence"],
        "needs_policy_verification": True,
        "recommended_status": "REVIEW_OR_BLOCK",
        "ocr_result": raw,
    }


@pytest.fixture(scope="module")
def scanner():
    return ResidualScanner.from_policy()


def test_overlap_fraction():
    assert overlap_fraction([0, 0, 1, 1], [0, 0, 1, 1]) == 1.0
    assert overlap_fraction([0, 0, 1, 1], [2, 2, 3, 3]) == 0.0
    assert overlap_fraction([0, 0, 2, 1], [1, 0, 2, 1]) == 0.5


def test_clean_reocr_passes(scanner):
    words = [{"word": "Risk Policy Section 4", "bbox": [0.1, 0.1, 0.5, 0.15], "confidence": 0.97},
             {"word": "SSN:", "bbox": [0.30, 0.40, 0.38, 0.45], "confidence": 0.95}]
    report = scanner.evaluate_ocr_result(_residual(words), redacted_boxes=BURNED)
    assert report.passed, report.to_dict()


def test_pii_in_reocr_text_is_a_leak(scanner):
    words = [{"word": "SSN: 219-45-7890", "bbox": [0.1, 0.7, 0.4, 0.75], "confidence": 0.93}]
    report = scanner.evaluate_ocr_result(_residual(words), redacted_boxes=BURNED)
    assert report.status_code == "RESIDUAL_LEAK_DETECTED"
    assert report.findings[0].source == "reocr"


def test_text_read_inside_burned_box_is_a_leak(scanner):
    # A fragment that no pattern recognizes, but it was read *inside* a burned area.
    words = [{"word": "45-78", "bbox": [0.45, 0.41, 0.55, 0.44], "confidence": 0.81}]
    report = scanner.evaluate_ocr_result(_residual(words), redacted_boxes=BURNED)
    assert "BURNED_REGION_TEXT" in {f.entity_type for f in report.findings}
    assert "45-78" not in str(report.to_dict())


def test_low_reocr_confidence_is_uncertain(scanner):
    words = [{"word": "blurry text", "bbox": [0.1, 0.1, 0.3, 0.15], "confidence": 0.41}]
    report = scanner.evaluate_ocr_result(_residual(words, confidence=0.41))
    assert report.uncertain and not report.passed


def test_unmapped_text_with_burned_boxes_is_uncertain(scanner):
    words = [{"word": "header", "bbox": [0.1, 0.1, 0.3, 0.15], "confidence": 0.9}]
    report = scanner.evaluate_ocr_result(_residual(words, unmapped=["fragment"]), redacted_boxes=BURNED)
    assert report.uncertain


def test_blank_page_is_clean(scanner):
    report = scanner.evaluate_ocr_result(_engine_result([], confidence=0.0), redacted_boxes=BURNED)
    assert report.passed


def test_accepts_raw_engine_output(scanner):
    words = [{"word": "Email alice@corp.com", "bbox": [0.1, 0.1, 0.5, 0.15], "confidence": 0.9}]
    report = scanner.evaluate_ocr_result(_engine_result(words))
    assert "EMAIL" in {f.entity_type for f in report.findings}


def test_malformed_input_fails_closed(scanner):
    report = scanner.evaluate_ocr_result({"ocr_result": "garbage"})
    assert report.uncertain and not report.passed


def test_ocr_failure_fails_closed(scanner):
    class BrokenEngine:
        def extract(self, *args, **kwargs):
            raise RuntimeError("paddle not installed")

    report = scanner.scan_image(b"not-an-image", page=3, engine=BrokenEngine())
    assert report.uncertain and not report.passed


def test_scan_pages_with_no_pages_is_uncertain(scanner):
    assert scanner.scan_pages({}, {}).uncertain


def test_dict_helper():
    words = [{"word": "SSN 219-45-7890", "bbox": [0.1, 0.1, 0.5, 0.15], "confidence": 0.9}]
    assert evaluate_residual(_residual(words))["status"] == "RESIDUAL_LEAK_DETECTED"
