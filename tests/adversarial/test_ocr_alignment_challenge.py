"""
Empirical Challenge Suite: Alignment, Padding, Variable-Width Text & Coordinate Scaling
Challenger M1-1 (Alignment & Padding Challenger)
Role: critic, specialist
Target Module: src/ocr/regions.py
"""

import os
import re
import inspect
import numpy as np
import pytest
from PIL import Image, ImageDraw, ImageFont

from src.ocr.regions import (
    find_pii_spans_in_text,
    extract_word_level_pii_boxes,
    char_width_weight,
    normalized_to_pixel,
    pixel_to_normalized,
)
from src.sanitization.image_redactor import redact_image
from src.sanitization.pdf_redactor import redact_scanned_pdf


def get_system_font(size: int = 24) -> ImageFont.FreeTypeFont:
    """Load a true type font available on the system."""
    font_paths = [
        "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/calibri.ttf",
        "C:/Windows/Fonts/times.ttf",
        "C:/Windows/Fonts/cour.ttf",
    ]
    for p in font_paths:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def render_and_measure_glyphs(text: str, font: ImageFont.FreeTypeFont, origin=(150, 400)):
    """
    Renders text and accurately determines the ink bounding box for the line and each character.
    Returns (line_bbox, char_bboxes).
    """
    img = Image.new("L", (1800, 800), 255)
    draw = ImageDraw.Draw(img)
    draw.text(origin, text, fill=0, font=font)
    arr = np.array(img)
    
    ink_ys, ink_xs = np.where(arr < 128)
    if len(ink_xs) == 0:
        return [origin[0], origin[1], origin[0] + 10, origin[1] + 10], []
    line_bbox = [int(ink_xs.min()), int(ink_ys.min()), int(ink_xs.max()), int(ink_ys.max())]

    char_bboxes = []
    x_curr = origin[0]
    for i, ch in enumerate(text):
        ch_w = font.getlength(ch)
        sub_img = Image.new("L", (1800, 800), 255)
        sub_draw = ImageDraw.Draw(sub_img)
        sub_draw.text((x_curr, origin[1]), ch, fill=0, font=font)
        sub_arr = np.array(sub_img)
        c_ys, c_xs = np.where(sub_arr < 128)
        if len(c_xs) > 0:
            c_bbox = [int(c_xs.min()), int(c_ys.min()), int(c_xs.max()), int(c_ys.max())]
        else:
            c_bbox = [int(x_curr), line_bbox[1], int(x_curr + ch_w), line_bbox[3]]
        char_bboxes.append(c_bbox)
        x_curr = origin[0] + font.getlength(text[:i+1])

    return line_bbox, char_bboxes


class TestVariableWidthAlignment:
    """Stress testing proportional alignment with narrow, wide, and punctuation characters."""

    @pytest.mark.parametrize("line_text, target_entity", [
        ("Rafael E: Duarte", "Rafael E: Duarte"),
        ("Devansh R. Kulkarni", "Devansh R. Kulkarni"),
        ("iii lll Rafael E: Duarte", "Rafael E: Duarte"),
        ("i: Devansh R. Kulkarni", "Devansh R. Kulkarni"),
        ("Approved by: Rafael E: Duarte", "Rafael E: Duarte"),
        ("Case review: Devansh R. Kulkarni", "Devansh R. Kulkarni"),
        ("MMM WWW Devansh R. Kulkarni", "Devansh R. Kulkarni"),
        ("MMWW Rafael E: Duarte", "Rafael E: Duarte"),
        ("Lead Auditor Desmond N. Quarshie confirmed", "Desmond N. Quarshie"),
        ("chaired by Priyanka S. Raghavan:", "Priyanka S. Raghavan"),
        ("Anthony P. Brightwell (DIR-0042)", "Anthony P. Brightwell"),
        ("Devansh R. Kulkarni (EMP-39220)", "Devansh R. Kulkarni"),
        ("Rafael E: Duarte (EMP-40944)", "Rafael E: Duarte"),
    ])
    def test_bounding_box_encloses_entity_with_zero_peeking(self, line_text, target_entity):
        font = get_system_font(24)
        img_w, img_h = 1700, 2200
        line_bbox, char_bboxes = render_and_measure_glyphs(line_text, font, origin=(150, 400))

        spans = find_pii_spans_in_text(line_text)
        assert len(spans) >= 1, f"Failed to detect PII span in '{line_text}'"

        target_span = None
        for s, e in spans:
            if line_text[s:e] == target_entity:
                target_span = (s, e)
                break
        assert target_span is not None, f"Target '{target_entity}' not in detected spans {spans}"

        s_idx, e_idx = target_span
        target_char_boxes = [char_bboxes[i] for i in range(s_idx, e_idx) if line_text[i] != " "]
        true_x0 = min(b[0] for b in target_char_boxes)
        true_x1 = max(b[2] for b in target_char_boxes)
        true_y0 = min(b[1] for b in target_char_boxes)
        true_y1 = max(b[3] for b in target_char_boxes)

        ocr_item = [(line_bbox, line_text)]
        boxes = extract_word_level_pii_boxes(ocr_item, img_w=img_w, img_h=img_h)
        assert len(boxes) >= 1

        matched_box = None
        for b in boxes:
            bx0 = b[0] * img_w
            bx1 = b[2] * img_w
            if bx0 <= true_x0 + 15 and bx1 >= true_x1 - 25:
                matched_box = [b[0]*img_w, b[1]*img_h, b[2]*img_w, b[3]*img_h]
                break

        assert matched_box is not None, f"No generated box covered target ink [{true_x0}, {true_x1}]"

        # 1. Zero Character Peeking verification
        assert matched_box[0] <= true_x0, f"Character peeking on left! Box x0={matched_box[0]:.1f} > ink x0={true_x0}"
        assert matched_box[2] >= true_x1, f"Character peeking on right! Box x1={matched_box[2]:.1f} < ink x1={true_x1}"
        assert matched_box[1] <= true_y0, f"Character peeking on top! Box y0={matched_box[1]:.1f} > ink y0={true_y0}"
        assert matched_box[3] >= true_y1, f"Character peeking on bottom! Box y1={matched_box[3]:.1f} < ink y1={true_y1}"

        # 2. Safety margin verification (at least 5px margin beyond ink)
        left_margin = true_x0 - matched_box[0]
        right_margin = matched_box[2] - true_x1
        top_margin = true_y0 - matched_box[1]
        bottom_margin = matched_box[3] - true_y1

        assert left_margin >= 5.0, f"Left margin ({left_margin:.2f}px) is less than 5px safety margin"
        assert right_margin >= 5.0, f"Right margin ({right_margin:.2f}px) is less than 5px safety margin"
        assert top_margin >= 5.0, f"Top margin ({top_margin:.2f}px) is less than 5px safety margin"
        assert bottom_margin >= 5.0, f"Bottom margin ({bottom_margin:.2f}px) is less than 5px safety margin"


class TestMiddleInitialDegradationsAndBridging:
    """Stress testing gap bridging across OCR degradation variants in middle initials."""

    def test_middle_initial_with_colon_bridged(self):
        text = "Rafael E: Duarte"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        assert text[spans[0][0]:spans[0][1]] == "Rafael E: Duarte"

    def test_middle_initial_with_dot_bridged(self):
        text = "Devansh R. Kulkarni"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        assert text[spans[0][0]:spans[0][1]] == "Devansh R. Kulkarni"

    def test_middle_initial_with_comma_degradation_bridged(self):
        # When OCR misrecognizes period as comma: "Devansh R, Kulkarni"
        # Must bridge interval so that " R, " is not exposed as an unredacted 20px gap
        text = "Devansh R, Kulkarni"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1, f"Failed to bridge comma-degraded middle initial: {spans}"
        assert text[spans[0][0]:spans[0][1]] == "Devansh R, Kulkarni"

    def test_middle_initial_bare_letter_bridged(self):
        text = "Anthony P Brightwell"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        assert text[spans[0][0]:spans[0][1]] == "Anthony P Brightwell"


class TestCoordinateScalingDPI:
    """Verify coordinate scaling invariance between 120 DPI and 200 DPI."""

    @pytest.mark.parametrize("dpi, width, height", [
        (120, 1020, 1320),
        (200, 1700, 2200),
        (300, 2550, 3300),
    ])
    def test_dpi_scaling_margin_invariance(self, dpi, width, height):
        line = "Tobias Lindqvist"
        scale = dpi / 120.0
        x0, y0, x1, y1 = 100.0 * scale, 200.0 * scale, 350.0 * scale, 240.0 * scale
        raw_box = [x0, y0, x1, y1]

        boxes = extract_word_level_pii_boxes([(raw_box, line)], img_w=width, img_h=height)
        assert len(boxes) == 1
        b = boxes[0]

        px_x0 = b[0] * width
        px_x1 = b[2] * width
        px_y0 = b[1] * height
        px_y1 = b[3] * height

        pad_left = x0 - px_x0
        pad_right = px_x1 - x1
        pad_top = y0 - px_y0
        pad_bottom = px_y1 - y1

        assert pad_left >= 5.0 - 1e-4, f"At {dpi} DPI, left pad {pad_left:.2f}px < 5.0px"
        assert pad_right >= 5.0 - 1e-4, f"At {dpi} DPI, right pad {pad_right:.2f}px < 5.0px"
        assert pad_top >= 5.0 - 1e-4, f"At {dpi} DPI, top pad {pad_top:.2f}px < 5.0px"
        assert pad_bottom >= 5.0 - 1e-4, f"At {dpi} DPI, bottom pad {pad_bottom:.2f}px < 5.0px"

        expected_norm_pad_x = 5.0 / 1020.0
        expected_norm_pad_y = 5.0 / 1320.0
        norm_pad_x = (x0 / width) - b[0]
        norm_pad_y = (y0 / height) - b[1]

        assert abs(norm_pad_x - expected_norm_pad_x) < 1e-5
        assert abs(norm_pad_y - expected_norm_pad_y) < 1e-5


class TestInterfaceContractConformity:
    """Verify function signatures conform to PROJECT.md interface contracts."""

    def test_extract_word_level_pii_boxes_has_padding_parameter(self):
        # PROJECT.md contract:
        # extract_word_level_pii_boxes(ocr_results: list[dict], width: int, height: int, padding: int = 5)
        sig = inspect.signature(extract_word_level_pii_boxes)
        assert "padding" in sig.parameters, "extract_word_level_pii_boxes signature missing 'padding' parameter"
        assert sig.parameters["padding"].default == 5, "extract_word_level_pii_boxes default padding should be 5"
