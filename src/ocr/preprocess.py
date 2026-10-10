
"""Image preprocessing helpers for OCR."""

from typing import Union

import cv2
import numpy as np
from PIL import Image


ImageInput = Union[Image.Image, np.ndarray, bytes, bytearray]


def to_rgb_array(image: ImageInput, input_is_bgr: bool = False) -> np.ndarray:
    """Convert supported image input into an RGB NumPy array."""
    if isinstance(image, (bytes, bytearray)):
        import io
        image = Image.open(io.BytesIO(image))

    if isinstance(image, Image.Image):
        return np.asarray(image.convert("RGB"))

    if isinstance(image, np.ndarray):
        if image.size == 0:
            raise ValueError("Input image is empty.")

        if image.ndim == 2:
            return cv2.cvtColor(image, cv2.COLOR_GRAY2RGB)

        if image.ndim != 3 or image.shape[2] not in (3, 4):
            raise ValueError("Expected a grayscale, RGB/BGR, or RGBA image.")

        if image.shape[2] == 4:
            if input_is_bgr:
                return cv2.cvtColor(image, cv2.COLOR_BGRA2RGB)
            return cv2.cvtColor(image, cv2.COLOR_RGBA2RGB)

        if input_is_bgr:
            return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)

        return image.copy()

    raise TypeError("Image must be bytes, PIL.Image, or NumPy array.")


def enhance_contrast(image_rgb: np.ndarray) -> np.ndarray:
    """Improve local contrast using CLAHE on the luminance channel."""
    lab = cv2.cvtColor(image_rgb, cv2.COLOR_RGB2LAB)
    lightness, channel_a, channel_b = cv2.split(lab)

    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    lightness = clahe.apply(lightness)

    enhanced = cv2.merge((lightness, channel_a, channel_b))
    return cv2.cvtColor(enhanced, cv2.COLOR_LAB2RGB)


def denoise(image_rgb: np.ndarray) -> np.ndarray:
    """Reduce noise while preserving text edges."""
    return cv2.fastNlMeansDenoisingColored(
        image_rgb, None, h=5, hColor=5, templateWindowSize=7, searchWindowSize=21
    )


def binarize(image_rgb: np.ndarray) -> np.ndarray:
    """Create a black-and-white image using Otsu thresholding."""
    gray = cv2.cvtColor(image_rgb, cv2.COLOR_RGB2GRAY)
    _, binary = cv2.threshold(
        gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
    )
    return cv2.cvtColor(binary, cv2.COLOR_GRAY2RGB)


def deskew(image_rgb: np.ndarray) -> np.ndarray:
    """Correct slight rotational skew in scanned documents or images."""
    gray = cv2.cvtColor(image_rgb, cv2.COLOR_RGB2GRAY)
    thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)[1]
    coords = np.column_stack(np.where(thresh > 0))
    if coords.size == 0:
        return image_rgb

    rect = cv2.minAreaRect(coords)
    angle = rect[-1]

    if angle < -45:
        angle = -(90 + angle)
    elif angle > 45:
        angle = 90 - angle
    else:
        angle = -angle

    if abs(angle) < 0.5 or abs(angle) > 45:
        return image_rgb

    h, w = image_rgb.shape[:2]
    center = (w // 2, h // 2)
    matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
    return cv2.warpAffine(
        image_rgb, matrix, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE
    )


def preprocess_image(
    image: ImageInput,
    input_is_bgr: bool = False,
    apply_binarization: bool = False,
    apply_denoising: bool = True,
    apply_deskew: bool = False,
) -> np.ndarray:
    """Return an OCR-ready RGB image with its original dimensions."""
    rgb = to_rgb_array(image, input_is_bgr=input_is_bgr)
    if apply_deskew:
        rgb = deskew(rgb)
    rgb = enhance_contrast(rgb)

    if apply_denoising:
        rgb = denoise(rgb)

    if apply_binarization:
        rgb = binarize(rgb)

    return rgb