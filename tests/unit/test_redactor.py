
import numpy as np
from PIL import Image

from src.sanitization.image_redactor import redact_image


def test_redaction_overwrites_pixels():
    source = Image.new("RGB", (100, 100), color="white")

    result = redact_image(
        source,
        boxes=[[0.2, 0.2, 0.4, 0.4]],
        padding=0,
    )

    pixels = np.array(result)

    # The normalized box maps to x=20..40, y=20..40.
    assert np.all(pixels[25, 25] == [0, 0, 0])
    assert np.all(pixels[10, 10] == [255, 255, 255])


def test_redaction_does_not_modify_original():
    source = Image.new("RGB", (100, 100), color="white")

    redact_image(source, [[0.2, 0.2, 0.4, 0.4]], padding=0)

    assert source.getpixel((25, 25)) == (255, 255, 255)


def test_redaction_clips_at_image_edges():
    source = Image.new("RGB", (20, 20), color="white")

    result = redact_image(
        source,
        boxes=[[0.0, 0.0, 0.1, 0.1]],
        padding=5,
    )

    assert result.getpixel((0, 0)) == (0, 0, 0)