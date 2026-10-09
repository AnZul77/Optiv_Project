
import numpy as np
from PIL import Image

from src.sanitization.image_redactor import redact_image


def test_padding_expands_redaction_area():
    image = Image.new("RGB", (100, 100), "white")

    box = [0.4, 0.4, 0.6, 0.6]

    result = redact_image(image, [box], padding=5)
    pixels = np.array(result)

    # Original box covers approximately pixels 40 through 59.
    # Padding should cover pixels immediately outside that box.
    assert np.all(pixels[39, 50] == 0)
    assert np.all(pixels[50, 39] == 0)
    assert np.all(pixels[60, 50] == 0)
    assert np.all(pixels[50, 60] == 0)


def test_original_image_is_unchanged():
    image = Image.new("RGB", (100, 100), "white")
    original_pixels = np.array(image).copy()

    box = [0.2, 0.2, 0.4, 0.4]
    redact_image(image, [box], padding=4)

    assert np.array_equal(
        np.array(image),
        original_pixels,
    )