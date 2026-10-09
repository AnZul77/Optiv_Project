
"""Re-OCR sanitized images to help detect residual text."""

from typing import Any, Dict, Union

import numpy as np
from PIL import Image

from src.ocr.engine import OCREngine


def scan_residual(
    image: Union[bytes, bytearray, Image.Image, np.ndarray],
    page: int = 1,
    engine: OCREngine = None,
) -> Dict[str, Any]:
    """Return residual OCR evidence; never declare the file safe by itself."""
    ocr = engine or OCREngine()
    result = ocr.extract(image, page=page)

    text_found = bool(result["text"].strip())
    uncertain = result["low_confidence"]

    return {
        "page": page,
        "residual_text_found": text_found,
        "residual_text": result["text"],
        "confidence": result["confidence"],
        "low_confidence": uncertain,
        "needs_policy_verification": True,
        "recommended_status": (
            "REVIEW_OR_BLOCK" if text_found or uncertain else "VERIFY"
        ),
        "ocr_result": result,
    }