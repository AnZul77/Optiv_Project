
from src.ocr.regions import (
    pixel_to_normalized,
    normalized_to_pixel,
)


def test_pixel_box_round_trip():
    original_box = [100, 200, 300, 400]
    image_width = 1000
    image_height = 800

    normalized = pixel_to_normalized(
        original_box,
        image_width,
        image_height,
    )

    restored = normalized_to_pixel(
        normalized,
        image_width,
        image_height,
    )

    assert restored == original_box


def test_normalized_box_conversion():
    normalized_box = [0.1, 0.25, 0.3, 0.5]

    pixels = normalized_to_pixel(
        normalized_box,
        1000,
        800,
    )

    assert pixels == [100, 200, 300, 400]


def test_full_image_box():
    normalized_box = [0.0, 0.0, 1.0, 1.0]

    pixels = normalized_to_pixel(
        normalized_box,
        1000,
        800,
    )

    assert pixels == [0, 0, 1000, 800]

import pytest

from src.ocr.regions import (
    pixel_to_normalized,
    normalized_to_pixel,
)


def test_invalid_image_dimensions_are_rejected():
    with pytest.raises((ValueError, ZeroDivisionError)):
        pixel_to_normalized([10, 10, 20, 20], 0, 100)


def test_negative_image_dimensions_are_rejected():
    with pytest.raises(ValueError):
        pixel_to_normalized([10, 10, 20, 20], -100, 100)


def test_invalid_normalized_box_is_rejected():
    with pytest.raises(ValueError):
        normalized_to_pixel(
            [0.8, 0.2, 0.3, 0.9],
            100,
            100,
        )