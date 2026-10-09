
import pytest

from src.ocr.confidence import assess_page, assess_words
from src.ocr.regions import pixel_to_normalized, normalized_to_pixel


def test_pixel_to_normalized():
    result = pixel_to_normalized(
        [100, 50, 300, 150],
        image_width=1000,
        image_height=500,
        page=1,
    )
    assert result == pytest.approx([0.1, 0.1, 0.3, 0.3])


def test_normalized_to_pixel():
    result = normalized_to_pixel(
        [0.1, 0.1, 0.3, 0.3],
        image_width=1000,
        image_height=500,
    )
    assert result == [100, 50, 300, 150]


def test_invalid_image_dimensions():
    with pytest.raises(ValueError):
        pixel_to_normalized([1, 2, 3, 4], 0, 100)


def test_low_confidence_word_is_flagged():
    result = assess_words([
        {"word": "example", "confidence": 0.55}
    ])
    assert result["low_confidence"] is True


def test_empty_page_is_flagged():
    result = assess_page("", 0.99)
    assert result["low_confidence"] is True


def test_high_confidence_page():
    result = assess_page("sample text", 0.95)
    assert result["low_confidence"] is False

def test_confidence_at_threshold_is_low_confidence():
    from src.ocr.confidence import assess_words

    words = [
        {"word": "test", "confidence": 0.60}
    ]

    result = assess_words(words)

    assert result["low_confidence"] is True


def test_confidence_below_threshold_is_low_confidence():
    from src.ocr.confidence import assess_words

    words = [
        {"word": "test", "confidence": 0.45}
    ]

    result = assess_words(words)

    assert result["low_confidence"] is True


def test_confidence_above_threshold_is_not_low_confidence():
    from src.ocr.confidence import assess_words

    words = [
        {"word": "test", "confidence": 0.95}
    ]

    result = assess_words(words)

    assert result["low_confidence"] is False

def test_empty_text_is_flagged():
    from src.ocr.confidence import assess_page

    result = assess_page("", 0.99)

    assert result["low_confidence"] is True


def test_whitespace_text_is_flagged():
    from src.ocr.confidence import assess_page

    result = assess_page("   ", 0.99)

    assert result["low_confidence"] is True