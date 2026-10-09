
"""Confidence checks used by the OCR safety pipeline."""

from typing import Any, Dict, List

LOW_CONFIDENCE_THRESHOLD = 0.60


def clamp_confidence(value: Any) -> float:
    """Return a confidence score bounded between 0 and 1."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0

    if score != score:  # NaN
        return 0.0

    return max(0.0, min(1.0, score))


def assess_words(
    words: List[Dict[str, Any]],
    threshold: float = LOW_CONFIDENCE_THRESHOLD,
) -> Dict[str, Any]:
    """Assess word-level confidence and flag uncertain OCR regions."""
    if not words:
        return {
            "confidence": 0.0,
            "low_confidence": True,
            "low_confidence_words": [],
            "reason": "OCR returned no words.",
        }

    scores = [clamp_confidence(word.get("confidence")) for word in words]
    low_words = [
        {**word, "confidence": score}
        for word, score in zip(words, scores)
        if score <= threshold
    ]

    return {
        "confidence": sum(scores) / len(scores),
        "low_confidence": bool(low_words),
        "low_confidence_words": low_words,
        "reason": (
            "One or more words are at or below the confidence threshold."
            if low_words
            else None
        ),
    }


def assess_page(
    text: str,
    confidence: Any,
    threshold: float = LOW_CONFIDENCE_THRESHOLD,
) -> Dict[str, Any]:
    """Conservatively assess a page-level OCR result."""
    score = clamp_confidence(confidence)

    if not text or not text.strip():
        return {
            "confidence": 0.0,
            "low_confidence": True,
            "reason": "OCR returned empty text.",
        }

    return {
        "confidence": score,
        "low_confidence": score <= threshold,
        "reason": (
            "Page confidence is at or below the threshold."
            if score <= threshold
            else None
        ),
    }