
import numpy as np
from PIL import Image

from src.sanitization.image_redactor import redact_image


def make_test_image(width=100, height=100):
    """Create a white image with a known black-and-white layout."""
    return Image.new("RGB", (width, height), "white")


def test_target_region_is_black():
    image = make_test_image()

    # Normalized box: x=20..40, y=20..40
    box = [0.2, 0.2, 0.4, 0.4]

    result = redact_image(image, [box], padding=0)
    pixels = np.array(result)

    # The central portion of the target must be black.
    assert np.all(pixels[22:38, 22:38] == 0)


def test_pixels_outside_target_are_unchanged():
    image = make_test_image()
    original = np.array(image).copy()

    box = [0.2, 0.2, 0.4, 0.4]
    result = redact_image(image, [box], padding=0)
    pixels = np.array(result)

    # A pixel far from the redaction must remain unchanged.
    assert np.array_equal(pixels[10, 10], original[10, 10])


def test_multiple_regions_are_redacted():
    image = make_test_image()

    boxes = [
        [0.1, 0.1, 0.2, 0.2],
        [0.7, 0.7, 0.9, 0.9],
    ]

    result = redact_image(image, boxes, padding=0)
    pixels = np.array(result)

    assert np.all(pixels[12:18, 12:18] == 0)
    assert np.all(pixels[72:88, 72:88] == 0)


def test_box_near_image_edge_does_not_crash():
    image = make_test_image()

    # The box touches the top-left edge.
    box = [0.0, 0.0, 0.1, 0.1]

    result = redact_image(image, [box], padding=4)

    assert result.size == image.size
    pixels = np.array(result)
    assert np.all(pixels[0:5, 0:5] == 0)