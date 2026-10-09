
"""OCR and vision utilities for the PII Security Firewall."""

from src.ocr.engine import OCREngine, extract_text
from src.ocr.confidence import (
    LOW_CONFIDENCE_THRESHOLD,
    assess_page,
    assess_words,
)
from src.ocr.regions import (
    make_bounding_box,
    normalized_to_pixel,
    pixel_to_normalized,
)

__all__ = [
    "OCREngine",
    "extract_text",
    "LOW_CONFIDENCE_THRESHOLD",
    "assess_page",
    "assess_words",
    "make_bounding_box",
    "normalized_to_pixel",
    "pixel_to_normalized",
]