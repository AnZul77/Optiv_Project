
"""Coordinate conversion helpers for OCR and redaction."""

from typing import Iterable, List, Sequence

from src.schema.document import BoundingBox


def pixel_to_normalized(
    bbox: Sequence[float],
    image_width: int,
    image_height: int,
    page: int = 1,
) -> List[float]:
    """Convert pixel coordinates to normalized coordinates."""
    if image_width <= 0 or image_height <= 0:
        raise ValueError("Image width and height must be positive.")

    if len(bbox) != 4:
        raise ValueError("Bounding box must contain four coordinates.")

    x0, y0, x1, y1 = map(float, bbox)

    if not all(map(lambda value: value == value and abs(value) != float("inf"), (x0, y0, x1, y1))):
        raise ValueError("Bounding box coordinates must be finite.")

    if x0 > x1 or y0 > y1:
        raise ValueError("Invalid pixel bounding box: minimum coordinates must not exceed maximum coordinates.")

    return [
        max(0.0, min(1.0, x0 / image_width)),
        max(0.0, min(1.0, y0 / image_height)),
        max(0.0, min(1.0, x1 / image_width)),
        max(0.0, min(1.0, y1 / image_height)),
    ]


def normalized_to_pixel(
    bbox: Sequence[float],
    image_width: int,
    image_height: int,
) -> List[int]:
    """Convert normalized coordinates into pixel coordinates."""
    if image_width <= 0 or image_height <= 0:
        raise ValueError("Image width and height must be positive.")

    if len(bbox) != 4:
        raise ValueError("Bounding box must contain four coordinates.")

    x0, y0, x1, y1 = map(float, bbox)

    if not all(map(lambda value: value == value and abs(value) != float("inf"), (x0, y0, x1, y1))):
        raise ValueError("Bounding box coordinates must be finite.")

    if not all(0.0 <= value <= 1.0 for value in (x0, y0, x1, y1)):
        raise ValueError("Normalized coordinates must be between 0 and 1.")

    if x0 > x1 or y0 > y1:
        raise ValueError(
            "Invalid bounding box: minimum coordinates "
            "must not exceed maximum coordinates."
        )

    return [
        round(x0 * image_width),
        round(y0 * image_height),
        round(x1 * image_width),
        round(y1 * image_height),
    ]


def make_bounding_box(
    pixel_bbox: Sequence[float],
    image_width: int,
    image_height: int,
    page: int = 1,
) -> BoundingBox:
    """Create the project's canonical BoundingBox from pixel coordinates."""
    coords = pixel_to_normalized(
        pixel_bbox, image_width, image_height, page
    )
    return BoundingBox.from_list(coords, page=page)


def polygon_to_pixel_bbox(
    polygon: Iterable[Sequence[float]],
) -> List[int]:
    """Convert polygon points into an enclosing pixel bounding rectangle."""
    points = list(polygon)

    if not points:
        raise ValueError("Polygon must contain at least one point.")

    if any(len(point) < 2 for point in points):
        raise ValueError("Each polygon point must contain at least two coordinates.")

    xs = [float(point[0]) for point in points]
    ys = [float(point[1]) for point in points]

    return [
        int(min(xs)),
        int(min(ys)),
        int(max(xs)),
        int(max(ys)),
    ]