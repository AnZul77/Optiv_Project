"""
Re-OCR Residual Scanner
=======================

Second look at pixel-burned images and PDF pages.

Person 2's `src.ocr.residual_scan.scan_residual()` re-OCRs a sanitized image
and returns raw evidence marked `needs_policy_verification: True`. This
module is that policy verification:

    1. Text check   - run the independent verifier over the re-OCR text.
    2. Burn check   - any OCR text region lying inside a burned box means the
                      burn did not obliterate the characters -> leak.
    3. Uncertainty  - a low mean re-OCR confidence, or recognized text with no
                      usable bounding box while burned boxes exist, means we
                      cannot vouch for the page -> uncertain (gate blocks).

Boxes are normalized [x0, y0, x1, y1], the same format Person 2's
redact_image() / redact_scanned_pdf(page_boxes=...) consume.

**Ownership:** Person 4 (Security Policy, Independent Verification & Audit)
"""

from __future__ import annotations

import math
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from src.schema.entities import compute_value_hash
from src.verification.verifier import (
    IndependentVerifier,
    ResidualFinding,
    VerificationReport,
)


def _box(values: Any) -> Optional[Sequence[float]]:
    try:
        x0, y0, x1, y1 = (float(v) for v in values)
    except (TypeError, ValueError):
        return None
    if not all(math.isfinite(v) for v in (x0, y0, x1, y1)) or x1 <= x0 or y1 <= y0:
        return None
    return x0, y0, x1, y1


def overlap_fraction(region: Sequence[float], burned: Sequence[float]) -> float:
    """Fraction of `region`'s area that lies inside `burned`."""
    rx0, ry0, rx1, ry1 = region
    bx0, by0, bx1, by1 = burned
    width = max(0.0, min(rx1, bx1) - max(rx0, bx0))
    height = max(0.0, min(ry1, by1) - max(ry0, by0))
    area = (rx1 - rx0) * (ry1 - ry0)
    return (width * height) / area if area > 0 else 0.0


class ResidualScanner:
    """Turns Person 2's re-OCR evidence into a VerificationReport."""

    def __init__(
        self,
        verifier: Optional[IndependentVerifier] = None,
        overlap_threshold: float = 0.30,
        min_reocr_confidence: float = 0.60,
    ):
        self.verifier = verifier or IndependentVerifier.from_policy()
        self.overlap_threshold = overlap_threshold
        self.min_reocr_confidence = min_reocr_confidence

    @classmethod
    def from_policy(cls, policy: Any = None) -> "ResidualScanner":
        if policy is None:
            from src.policy.policy import PolicyConfig
            policy = PolicyConfig.load()
        config = getattr(policy, "config", policy)
        settings = config.verification.get("residual_scan", {})
        return cls(
            verifier=IndependentVerifier.from_policy(config),
            overlap_threshold=float(settings.get("burned_box_overlap_threshold", 0.30)),
            min_reocr_confidence=float(settings.get("min_reocr_confidence", 0.60)),
        )

    def evaluate_ocr_result(
        self,
        ocr_result: Mapping[str, Any],
        page: Optional[int] = None,
        unit_id: Optional[str] = None,
        redacted_boxes: Iterable[Sequence[float]] = (),
    ) -> VerificationReport:
        """
        Evaluate one re-OCR result.

        Accepts either Person 2's scan_residual() dict (residual_text, ocr_result, ...)
        or a raw OCREngine.extract() dict (text, words, confidence, ...).
        """
        try:
            raw = ocr_result.get("ocr_result") or ocr_result
            page = int(page if page is not None else ocr_result.get("page", raw.get("page", 1)) or 1)
            unit_id = unit_id or f"reocr_page_{page}"
            text = ocr_result.get("residual_text", raw.get("text", "")) or ""
            boxes = [b for b in (_box(v) for v in redacted_boxes) if b is not None]

            report = self.verifier.verify_text(text, page=page, unit_id=unit_id, source="reocr") \
                if text.strip() else VerificationReport(units_scanned=1)

            for word in raw.get("words", []) or []:
                region = _box(word.get("bbox"))
                if region is None:
                    continue
                if any(overlap_fraction(region, b) >= self.overlap_threshold for b in boxes):
                    word_text = str(word.get("word", word.get("text", "")))
                    report.findings.append(ResidualFinding(
                        entity_type="BURNED_REGION_TEXT",
                        risk="CRITICAL",
                        detector="reocr_burned_box",
                        page=page,
                        unit_id=unit_id,
                        source="reocr",
                        start=0,
                        end=len(word_text),
                        value_hash=compute_value_hash(word_text),
                        confidence=float(word.get("confidence", 0.0) or 0.0),
                    ))

            if text.strip():
                confidence = float(ocr_result.get("confidence", raw.get("confidence", 0.0)) or 0.0)
                if not math.isfinite(confidence) or confidence <= self.min_reocr_confidence:
                    report.uncertain = True
                    report.errors.append(
                        f"{unit_id}: re-OCR confidence {confidence:.2f} at or below "
                        f"{self.min_reocr_confidence:.2f}"
                    )
            if boxes and raw.get("unmapped_text"):
                report.uncertain = True
                report.errors.append(
                    f"{unit_id}: re-OCR text without bounding boxes; burned regions cannot be confirmed"
                )
            return report

        except Exception as exc:  # fail closed
            return VerificationReport(
                uncertain=True,
                errors=[f"residual scan error on page {page}: {type(exc).__name__}"],
                units_scanned=1,
            )

    def scan_image(
        self,
        image: Any,
        page: int = 1,
        redacted_boxes: Iterable[Sequence[float]] = (),
        engine: Any = None,
        unit_id: Optional[str] = None,
    ) -> VerificationReport:
        """Re-OCR one sanitized image with Person 2's engine, then evaluate it."""
        try:
            from src.ocr.residual_scan import scan_residual  # needs PaddleOCR at runtime

            evidence = scan_residual(image, page=page, engine=engine)
        except Exception as exc:  # OCR unavailable or failed -> cannot verify
            return VerificationReport(
                uncertain=True,
                errors=[f"re-OCR failed on page {page}: {type(exc).__name__}"],
                units_scanned=1,
            )
        return self.evaluate_ocr_result(evidence, page=page, unit_id=unit_id,
                                        redacted_boxes=redacted_boxes)

    def scan_pages(
        self,
        page_images: Mapping[int, Any],
        page_boxes: Mapping[int, Iterable[Sequence[float]]],
        engine: Any = None,
    ) -> VerificationReport:
        """Re-OCR every sanitized page; `page_boxes` is the map given to redact_scanned_pdf()."""
        report = VerificationReport()
        for page_num in sorted(page_images):
            report = report.merge(self.scan_image(
                page_images[page_num], page=page_num,
                redacted_boxes=page_boxes.get(page_num, []), engine=engine,
            ))
        if report.units_scanned == 0:
            report.uncertain = True
            report.errors.append("residual scan received no pages")
        return report


def evaluate_residual(
    ocr_result: Mapping[str, Any],
    redacted_boxes: Iterable[Sequence[float]] = (),
    policy: Any = None,
) -> Dict[str, Any]:
    """Dict-in / dict-out helper for callers that just want the verdict."""
    report = ResidualScanner.from_policy(policy).evaluate_ocr_result(
        ocr_result, redacted_boxes=redacted_boxes
    )
    return report.to_dict()
