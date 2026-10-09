
"""Irreversible pixel redaction for images."""

from typing import Iterable, Sequence, Tuple, Union

import numpy as np
from PIL import Image

from src.ocr.regions import normalized_to_pixel


def redact_image(
    image: Union[Image.Image, np.ndarray],
    boxes: Iterable[Sequence[float]],
    padding: int = 4,
    color: Tuple[int, int, int] = (0, 0, 0),
) -> Image.Image:
    """
    Return an image with normalized bounding boxes overwritten with solid pixels.

    Each box is [x0, y0, x1, y1] in normalized coordinates.
    """
    if padding < 0:
        raise ValueError("Padding cannot be negative.")

    if isinstance(image, Image.Image):
        output = image.convert("RGB").copy()
    elif isinstance(image, np.ndarray):
        if image.ndim == 2:
            output = Image.fromarray(image).convert("RGB")
        elif image.ndim == 3:
            output = Image.fromarray(image.astype(np.uint8)).convert("RGB")
        else:
            raise ValueError("Unsupported NumPy image shape.")
    else:
        raise TypeError("Image must be a PIL image or NumPy array.")

    pixels = np.array(output)
    height, width = pixels.shape[:2]

    for box in boxes:
        x0, y0, x1, y1 = normalized_to_pixel(box, width, height)

        left = max(0, x0 - padding)
        top = max(0, y0 - padding)
        right = min(width, x1 + padding)
        bottom = min(height, y1 + padding)

        if right <= left or bottom <= top:
            continue

        pixels[top:bottom, left:right] = color

    return Image.fromarray(pixels)


def redact_image_bytes(
    image_bytes: bytes,
    boxes: Iterable[Sequence[float]],
    padding: int = 4,
) -> bytes:
    """Redact an image supplied as bytes and return sanitized PNG bytes."""
    import io

    with Image.open(io.BytesIO(image_bytes)) as image:
        sanitized = redact_image(image, boxes, padding=padding)

    buffer = io.BytesIO()
    sanitized.save(buffer, format="PNG")
    return buffer.getvalue()