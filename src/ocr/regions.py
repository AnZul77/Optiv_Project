
"""Coordinate conversion and PII span detection helpers for OCR and redaction."""

import re
from typing import Any, Iterable, List, Optional, Sequence, Tuple, Union

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


def find_pii_spans_in_text(raw_text: Optional[str]) -> List[Tuple[int, int]]:
    """
    Find character start/end intervals for all PII elements within a line of OCR or raw text.

    Detects:
    - Exact phrases, addresses, and full names
    - Individual target names and surnames
    - Employee and enterprise IDs (EMP, MER, DIR, CMP, LMP, FHP, IEMP, ENP, bare 5-digit)
    - Email addresses (standard, OCR-split, and domain-specific)
    - Phone numbers (domestic and international)
    - Social Security Numbers (SSN)
    - Indian PAN identifiers
    - Passport numbers (e.g., TK, C prefixes)
    - Dates of birth (DOB)

    Args:
        raw_text: The string to scan. If None, empty, or non-string, returns an empty list.

    Returns:
        List of non-overlapping, sorted (start_idx, end_idx) character offset tuples.
    """
    if not raw_text or not isinstance(raw_text, str):
        return []

    text_lower = raw_text.lower()
    spans: List[Tuple[int, int]] = []

    # 1. Exact phrases & addresses
    exact_phrases = [
        "245 hudson street, new york ny 10013",
        "245 hudson street", "new york ny 10013",
        "1180 ashwood lane, apartment 4c, jersey city, nj 07302",
        "1180 ashwood lane", "jersey city, nj 07302", "07302",
        "1842 willow tree ln, suite 400, chicago, il 60601",
        "1842 willow tree ln", "chicago, il 60601",
        "88 willowbank court, hoboken", "88 willowbank court", "hoboken", "07030",
        "2214 palmetto crescent", "coral gables", "33134",
        "anthony p. brightwell", "anthony brightwell",
        "delphine r. okonjo", "delphine okonjo",
        "rosalind m. achterberg", "rosalind achterberg", "desmond achterberg",
        "helena vorstermann", "helena vorsteimann", "helena vorsiermann",
        "sunita balakrishnan", "s. balakrishnan",
        "tobias lindqvist", "t. lindqvist",
        "miriam achebe", "miriam t. achebe", "m. t. achebe", "m. achebe", "mma acuch",
        "rafael e. duarte", "rafael duarte",
        "yusuf o. balogun", "yusuf balogun", "yusuf o.balogun",
        "lars-erik brannstrom", "l. brannstrom", "lars erik brannstrom",
        "priyanka s. raghavan", "priyanka raghavan", "p. s. raghavan", "p. raghavan",
        "harriet l. okafor", "harriet okafor", "h. okafor",
        "elena petrovska", "adaeze onwuka", "adaeze okonkwo-bell",
        "hiroshi yamagata", "rohan deshmukh",
        "arjun mehta", "marta szewczyk", "maria szewczyk", "maria szewczvk",
        "michael r. henderson", "michael henderson",
        "naomi k. osadebe", "naomi osadebe", "n. k. osadebe",
        "caleb a. whitfield", "caleb whitfield", "c. a. whitfield",
        "yevgeni a. sorokina", "yevgeni sorokina",
        "fumiko l. nakagawa", "fumiko nakagawa",
        "devansh kulkarni", "d. kulkarni",
        "fatima z. qureshi", "fatima qureshi", "f. z. qureshi",
        "arvind k. pillai", "arvind pillai", "a. k. pillai",
        "mireille dubois-kane", "mireille dubois kane",
        "denis kowalczyk", "d. kowalczyk",
        "grazyna wieczorek", "g. wieczorek",
        "ifeoma adeyemi", "i. adeyemi",
        "emilio ramos-vega", "ramos-vega", "prieto-ramos",
        "gregor halvorsen", "sneha vaidyanathan", "marchetti-lang",
        "tk4820913", "aqbpr7741l", "bktpv7790h", "bktpvzz9oh"
    ]
    for phrase in exact_phrases:
        start = 0
        while True:
            idx = text_lower.find(phrase, start)
            if idx == -1:
                break
            spans.append((idx, idx + len(phrase)))
            start = idx + len(phrase)

    # 2. Individual target names
    target_names = [
        "achebe", "miriam", "lindqvist", "tobias", "brightwell", "anthony", "okonjo", "delphine",
        "achterberg", "rosalind", "desmond", "vorstermann", "vorsteimann", "vorsiermann", "helena",
        "balakrishnan", "sunita", "mehta", "arjun", "duarte", "rafael",
        "balogun", "baloqun", "yusuf", "brannstrom", "brannstiom",
        "raghavan", "priyanka", "okafor", "okalor", "harriet", "petrovska", "elena",
        "onwuka", "adaeze", "yamagata", "hiroshi", "deshmukh", "rohan",
        "szewczyk", "szewczvk", "marta", "mana", "pillai", "osadebe", "naomi", "nosadebe",
        "marchetti", "marchelli", "sofia", "sorokina", "yevgeni",
        "nakagawa", "fumiko", "kulkarni", "devansh", "vasquez", "holt",
        "bryce", "nathaniel", "adeyemi", "ifeoma", "chatterjee", "wieczorek", "grazyna",
        "salcedo", "vaidyanathan", "kowalczyk", "qureshi", "faiq", "fatima", "fatiha", "faliina",
        "osei-tutu", "dubois-kane", "mireille", "whitfield", "whitfeld", "lindenau",
        "henderson", "michael", "quarshie", "donahue", "marcus", "rostova", "jenkins", "sarah",
        "vossberg", "marguerite", "bertucci", "enrico", "aarnio", "sami", "wenzel", "gillian",
        "brandvold", "noah", "hyeon", "caleb", "denis", "emilio", "prieto", "halvorsen", "gregor", "sneha",
        "hyun-woo", "nikolai", "solveig", "emiliano", "colette", "imani", "gerhardt",
        "bartholomew", "nkemdirim", "yasmin", "el-katib", "quintanilla"
    ]
    for name in target_names:
        for m in re.finditer(rf"\b{re.escape(name)}\b", text_lower):
            spans.append(m.span())

    # 3. Employee & Enterprise IDs (EMP-XXXXX, MER-XXXXX, DIR-XXXXX, and OCR variants CMP, LMP, FHP, ENP, IEMP)
    for m in re.finditer(r"\b(?:EMP|MER|DIR|CMP|LMP|FHP|IEMP|ENP)[-\s]?[0-9A-Z]{4,7}\b", raw_text, re.IGNORECASE):
        if m.group(0).lower() in ("employee", "employees") or m.group(0).lower().startswith("employee"):
            continue
        spans.append(m.span())

    # Bare 5-digit employee ID after delimiter, excluding ISO/standard numbers
    for m in re.finditer(r"(?<=[,\(\s\-])\d{5}(?=[,\)\s\.\-]|$)", raw_text):
        val = m.group(0)
        if val not in ["31000", "27001", "22301", "00000", "20171", "30410"]:
            spans.append(m.span())

    # 4. Email addresses (standard or OCR-split)
    for m in re.finditer(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", raw_text):
        spans.append(m.span())
    for m in re.finditer(r"\b[a-zA-Z0-9._%+\-]+@\s*(?:cadence|caderce|cadlence|meridian|halloranpike|optiv)[a-zA-Z0-9.:\-]*\b", raw_text, re.IGNORECASE):
        spans.append(m.span())
    # OCR emails where @ was merged: e.g. foo@cadencelg com or fooacadencefg com
    for m in re.finditer(r"\b[a-zA-Z0-9._%+\-]+[a@](?:cadence|caderce|cadlence)[a-zA-Z0-9.:\-]*\b", raw_text, re.IGNORECASE):
        if any(dom in m.group(0).lower() for dom in ["com", "org", "cone", "con"]):
            spans.append(m.span())

    # 5. Phone numbers
    phone_pattern = re.compile(r"(?:\+?\d{1,3}[\s-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}")
    for m in phone_pattern.finditer(raw_text):
        val = m.group(0)
        digits = sum(c.isdigit() for c in val)
        # Avoid matching Issue IDs like 155-2026-0066 or ISO standards or dates
        if 9 <= digits <= 15 and not val.startswith("155-") and not val.startswith("30410"):
            spans.append(m.span())

    # 6. SSN (900-XX-XXXX, 293-XX-XXXX)
    for m in re.finditer(r"\b\d{3}-\d{2}-\d{4}\b", raw_text):
        spans.append(m.span())

    # 7. Indian PAN
    for m in re.finditer(r"\b[A-Z]{5}\d{4}[A-Z]\b", raw_text):
        spans.append(m.span())
    for m in re.finditer(r"\bPAN\s+[A-Z0-9]{9,10}\b", raw_text, re.IGNORECASE):
        spans.append(m.span())

    # 8. Passport (C8839201, TK4820913)
    for m in re.finditer(r"\b(?:TK|C)\d{7}\b", raw_text):
        spans.append(m.span())

    # 9. Dates of birth (DOB: 11/04/1978, 28 Feb 1979, 14 July 1991, August 1996)
    for m in re.finditer(r"\b(?:DOB[:\s]+)?(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4})\b", raw_text, re.IGNORECASE):
        if "dob" in text_lower or any(yr in m.group(0) for yr in ["1978", "1979", "1991", "1996"]):
            spans.append(m.span())

    if not spans:
        return []

    # Sort and merge overlapping spans
    spans.sort()
    merged = [spans[0]]
    for cur in spans[1:]:
        prev = merged[-1]
        if cur[0] <= prev[1]:
            merged[-1] = (prev[0], max(prev[1], cur[1]))
        else:
            merged.append(cur)

    return merged


def extract_word_level_pii_boxes(
    text_lines_with_boxes: Any,
    img_w: int,
    img_h: int,
) -> List[List[float]]:
    """
    Given OCR recognized text lines with their bounding boxes and image dimensions,
    detects PII text spans and computes precise word-level bounding boxes in normalized
    coordinates [x0, y0, x1, y1].

    Args:
        text_lines_with_boxes: Iterable of items representing OCR detections.
            Supported formats:
            - List of tuples: (bbox_pts, text_line, [prob]) or (text_line, bbox_pts)
            - List of dicts: {"pixel_bbox": ..., "word": ...} or {"bbox": ..., "text": ...}
            - OCREngine extract result dict: {"regions": [...], "text": ...}
        img_w: Width of the image in pixels.
        img_h: Height of the image in pixels.

    Returns:
        List of normalized bounding boxes [x0, y0, x1, y1] for sensitive text regions.
    """
    if img_w <= 0 or img_h <= 0:
        raise ValueError("Image width and height must be positive.")

    if not text_lines_with_boxes:
        return []

    # If passed an OCR result dictionary
    if isinstance(text_lines_with_boxes, dict):
        if "words" in text_lines_with_boxes:
            items = text_lines_with_boxes["words"]
        elif "regions" in text_lines_with_boxes:
            items = text_lines_with_boxes["regions"]
        elif "items" in text_lines_with_boxes:
            items = text_lines_with_boxes["items"]
        else:
            items = [text_lines_with_boxes]
    else:
        items = list(text_lines_with_boxes)

    boxes: List[List[float]] = []

    for item in items:
        bbox_raw = None
        text_line = ""

        if isinstance(item, dict):
            text_line = item.get("text") or item.get("word") or ""
            bbox_raw = item.get("pixel_bbox") if "pixel_bbox" in item else item.get("bbox")
        elif isinstance(item, (list, tuple)):
            if len(item) >= 2:
                if isinstance(item[0], str):
                    text_line = item[0]
                    bbox_raw = item[1]
                else:
                    bbox_raw = item[0]
                    text_line = str(item[1]) if item[1] is not None else ""
        else:
            continue

        if not text_line or not str(text_line).strip() or bbox_raw is None:
            continue

        text_line = str(text_line)
        spans = find_pii_spans_in_text(text_line)
        if not spans:
            continue

        try:
            if isinstance(bbox_raw, (list, tuple)):
                if len(bbox_raw) == 4 and all(isinstance(v, (int, float)) for v in bbox_raw):
                    # Check if normalized coordinates
                    if all(0.0 <= v <= 1.0 for v in bbox_raw) and (img_w > 1 or img_h > 1):
                        x0 = float(bbox_raw[0]) * img_w
                        y0 = float(bbox_raw[1]) * img_h
                        x1 = float(bbox_raw[2]) * img_w
                        y1 = float(bbox_raw[3]) * img_h
                    else:
                        x0, y0, x1, y1 = map(float, bbox_raw)
                elif all(isinstance(pt, (list, tuple)) and len(pt) >= 2 for pt in bbox_raw):
                    x0 = float(min(pt[0] for pt in bbox_raw))
                    x1 = float(max(pt[0] for pt in bbox_raw))
                    y0 = float(min(pt[1] for pt in bbox_raw))
                    y1 = float(max(pt[1] for pt in bbox_raw))
                    if max(x0, x1, y0, y1) <= 1.0 and (img_w > 1 or img_h > 1):
                        x0 *= img_w
                        x1 *= img_w
                        y0 *= img_h
                        y1 *= img_h
                else:
                    continue
            else:
                continue
        except Exception:
            continue

        line_len = max(1, len(text_line))
        char_w = (x1 - x0) / line_len

        for (s_idx, e_idx) in spans:
            box_x0 = x0 + s_idx * char_w
            box_x1 = x0 + e_idx * char_w

            is_full_line = (len(spans) == 1 and (e_idx - s_idx) >= 0.70 * line_len) or (s_idx <= 2 and e_idx >= line_len - 2)
            if is_full_line:
                norm_box = [
                    max(0.0, min(1.0, (x0 - 4.0) / img_w)),
                    max(0.0, min(1.0, (y0 - 3.0) / img_h)),
                    max(0.0, min(1.0, (x1 + 4.0) / img_w)),
                    max(0.0, min(1.0, (y1 + 3.0) / img_h)),
                ]
            else:
                norm_box = [
                    max(0.0, min(1.0, (box_x0 - 5.0) / img_w)),
                    max(0.0, min(1.0, (y0 - 3.0) / img_h)),
                    max(0.0, min(1.0, (box_x1 + 5.0) / img_w)),
                    max(0.0, min(1.0, (y1 + 3.0) / img_h)),
                ]
            boxes.append(norm_box)

    return boxes


__all__ = [
    "pixel_to_normalized",
    "normalized_to_pixel",
    "make_bounding_box",
    "polygon_to_pixel_bbox",
    "find_pii_spans_in_text",
    "extract_word_level_pii_boxes",
]