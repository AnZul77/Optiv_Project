
from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

from src.ocr.confidence import clamp_confidence
from src.ocr.preprocess import preprocess_image


class OCREngine:
    """
    OCR adapter for PaddleOCR 3.x.

    Supported inputs:
        - Image file path
        - Image bytes
        - PIL Image
        - NumPy image array

    Output coordinates:
        bbox       -> normalized [x0, y0, x1, y1] coordinates
        pixel_bbox -> pixel coordinates [x0, y0, x1, y1]

    PaddleOCR boxes represent text regions, not necessarily individual words.
    Recognized text that cannot be mapped safely is preserved and flagged.
    """

    LOW_CONFIDENCE_THRESHOLD = 0.60

    def __init__(self, lang: str = "en") -> None:
        self.lang = lang
        self._ocr = None

    def _get_ocr(self):
        """Initialize PaddleOCR lazily."""
        if self._ocr is None:
            from paddleocr import PaddleOCR

            self._ocr = PaddleOCR(
                lang=self.lang,
                enable_mkldnn=False,
            )

        return self._ocr

    @staticmethod
    def _load_image(
        source: bytes | bytearray | Image.Image | np.ndarray | str | Path,
    ) -> np.ndarray:
        """Load an image and return an RGB uint8 NumPy array."""

        if isinstance(source, (str, Path)):
            with Image.open(source) as image:
                return np.asarray(image.convert("RGB")).copy()

        if isinstance(source, (bytes, bytearray)):
            with Image.open(BytesIO(source)) as image:
                return np.asarray(image.convert("RGB")).copy()

        if isinstance(source, Image.Image):
            return np.asarray(source.convert("RGB")).copy()

        if isinstance(source, np.ndarray):
            if source.size == 0:
                raise ValueError("Input image array is empty.")

            if source.dtype != np.uint8:
                source = np.clip(source, 0, 255).astype(np.uint8)

            if source.ndim == 2:
                return np.repeat(source[:, :, None], 3, axis=2)

            if source.ndim == 3 and source.shape[2] == 4:
                return np.asarray(
                    Image.fromarray(source).convert("RGB")
                ).copy()

            if source.ndim == 3 and source.shape[2] == 3:
                return source.copy()

            raise ValueError(
                "Image array must be grayscale, RGB, or RGBA."
            )

        raise TypeError(
            "Unsupported image input. Provide image bytes, a PIL Image, "
            "a NumPy array, or an image path."
        )

    @staticmethod
    def _parse_paddle_result(
        result: Any,
    ) -> list[dict[str, Any]]:
        """
        Parse PaddleOCR 3.x predict() results.

        Preserve recognized text even if its bounding box is missing or
        invalid, so the caller can flag the document for review.
        """

        items: list[dict[str, Any]] = []

        if not isinstance(result, list):
            return items

        for page_result in result:
            if not isinstance(page_result, dict):
                continue

            texts = page_result.get("rec_texts") or []
            scores = page_result.get("rec_scores")
            boxes = page_result.get("rec_boxes")

            for index, raw_text in enumerate(texts):
                recognized_text = str(raw_text).strip()

                if not recognized_text:
                    continue

                # Missing or invalid confidence is not treated as safe.
                try:
                    if scores is not None and index < len(scores):
                        score = clamp_confidence(float(scores[index]))
                    else:
                        score = 0.0
                except (TypeError, ValueError, OverflowError):
                    score = 0.0

                # Keep the text even when there is no corresponding box.
                if boxes is None or index >= len(boxes):
                    items.append({
                        "text": recognized_text,
                        "confidence": score,
                        "mapping_error": "Missing bounding box",
                    })
                    continue

                try:
                    box = np.asarray(boxes[index]).reshape(-1)

                    if len(box) < 4:
                        raise ValueError(
                            "Bounding box has fewer than 4 values."
                        )

                    x0, y0, x1, y1 = map(float, box[:4])

                    if not np.all(
                        np.isfinite([x0, y0, x1, y1])
                    ):
                        raise ValueError(
                            "Bounding box contains non-finite values."
                        )

                    if x1 <= x0 or y1 <= y0:
                        raise ValueError(
                            "Bounding box has invalid dimensions."
                        )

                    items.append({
                        "text": recognized_text,
                        "confidence": score,
                        "pixel_bbox": [x0, y0, x1, y1],
                    })

                except (TypeError, ValueError, IndexError, OverflowError) as exc:
                    items.append({
                        "text": recognized_text,
                        "confidence": score,
                        "mapping_error": str(exc),
                    })

        return items

    def extract(
        self,
        source: bytes | bytearray | Image.Image | np.ndarray | str | Path,
        page: int = 1,
    ) -> dict[str, Any]:
        """Recognize text and return regions, coordinates, and warnings."""

        if page < 1:
            raise ValueError("Page number must be at least 1.")

        rgb_image = self._load_image(source)
        height, width = rgb_image.shape[:2]

        if width <= 0 or height <= 0:
            raise ValueError("Input image has invalid dimensions.")

        processed = preprocess_image(rgb_image)

        if processed.shape[:2] != (height, width):
            raise ValueError(
                "Preprocessing changed image dimensions. "
                "Bounding-box coordinates cannot be mapped safely."
            )

        ocr = self._get_ocr()
        raw_result = ocr.predict(processed)
        items = self._parse_paddle_result(raw_result)

        regions: list[dict[str, Any]] = []
        unmapped_text: list[str] = []
        warnings: list[str] = []

        for item in items:
            if "mapping_error" in item:
                unmapped_text.append(item["text"])
                warnings.append(
                    "Recognized text could not be mapped safely to a "
                    f"bounding box: {item['mapping_error']}"
                )
                continue

            x0, y0, x1, y1 = item["pixel_bbox"]

            # Clip coordinates to the image boundaries.
            x0 = max(0.0, min(float(width), x0))
            x1 = max(0.0, min(float(width), x1))
            y0 = max(0.0, min(float(height), y0))
            y1 = max(0.0, min(float(height), y1))

            if x1 <= x0 or y1 <= y0:
                unmapped_text.append(item["text"])
                warnings.append(
                    "Recognized text has no usable bounding box "
                    "after coordinate validation."
                )
                continue

            normalized_bbox = [
                x0 / width,
                y0 / height,
                x1 / width,
                y1 / height,
            ]

            regions.append({
                # Compatibility key: this may represent a whole text region.
                "word": item["text"],
                "bbox": normalized_bbox,
                "pixel_bbox": [x0, y0, x1, y1],
                "confidence": item["confidence"],
                "page": page,
            })

        # Preserve all recognized text, including text without safe boxes.
        recognized_parts = [
            region["word"] for region in regions
        ] + unmapped_text

        recognized_text = "\n".join(recognized_parts)

        confidence_values = [
            region["confidence"] for region in regions
        ] + [
            item["confidence"]
            for item in items
            if "mapping_error" in item
        ]

        mean_confidence = (
            sum(confidence_values) / len(confidence_values)
            if confidence_values
            else 0.0
        )

        low_confidence = (
            not regions
            or bool(unmapped_text)
            or any(
                confidence <= self.LOW_CONFIDENCE_THRESHOLD
                for confidence in confidence_values
            )
        )

        return {
            "text": recognized_text,
            "confidence": clamp_confidence(mean_confidence),
            "words": regions,
            "width": width,
            "height": height,
            "low_confidence": low_confidence,
            "engine": "PaddleOCR",
            "page": page,
            "unmapped_text": unmapped_text,
            "warnings": warnings,
            "requires_review": bool(warnings),
        }

    def extract_text(
        self,
        source: bytes | bytearray | Image.Image | np.ndarray | str | Path,
    ) -> str:
        """Return recognized text only."""
        return self.extract(source)["text"]


def extract_text(
    source: bytes | bytearray | Image.Image | np.ndarray | str | Path,
) -> str:
    """Module-level compatibility wrapper for existing imports."""
    return OCREngine().extract_text(source)