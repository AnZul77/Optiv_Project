
from pathlib import Path

import pytest
from PIL import Image
from pypdf import PdfReader

from src.sanitization.pdf_redactor import redact_scanned_pdf


def test_missing_input_pdf_raises_error(tmp_path):
    missing_pdf = tmp_path / "missing.pdf"
    output_pdf = tmp_path / "output.pdf"

    with pytest.raises(FileNotFoundError):
        redact_scanned_pdf(
            missing_pdf,
            output_pdf,
            page_boxes={},
        )


def test_same_input_and_output_path_raises_error(tmp_path):
    pdf_path = tmp_path / "sample.pdf"
    pdf_path.write_bytes(b"%PDF-test")

    with pytest.raises(ValueError, match="different"):
        redact_scanned_pdf(
            pdf_path,
            pdf_path,
            page_boxes={},
        )


def test_dpi_below_minimum_raises_error(tmp_path):
    pdf_path = tmp_path / "sample.pdf"
    pdf_path.write_bytes(b"%PDF-test")

    with pytest.raises(ValueError, match="DPI"):
        redact_scanned_pdf(
            pdf_path,
            tmp_path / "output.pdf",
            page_boxes={},
            dpi=50,
        )

from reportlab.pdfgen import canvas
from pdf2image import convert_from_path



def test_redact_scanned_pdf_blacks_target_region(tmp_path):
    from reportlab.pdfgen import canvas
    from pdf2image import convert_from_path
    from src.sanitization.pdf_redactor import redact_scanned_pdf

    poppler_path = r"C:\poppler-26.09.0\Library\bin"

    input_pdf = tmp_path / "synthetic.pdf"
    output_pdf = tmp_path / "redacted.pdf"

    pdf = canvas.Canvas(str(input_pdf), pagesize=(200, 200))
    pdf.drawString(40, 100, "Synthetic test document")
    pdf.save()

    page_boxes = {
        1: [[0.25, 0.25, 0.75, 0.75]]
    }

    redact_scanned_pdf(
        str(input_pdf),
        str(output_pdf),
        page_boxes,
        dpi=100,
        padding=0,
        poppler_path=poppler_path,
    )

    pages = convert_from_path(
        str(output_pdf),
        dpi=100,
        poppler_path=poppler_path,
    )

    assert len(pages) == 1

    image = pages[0].convert("RGB")
    width, height = image.size

    center_pixel = image.getpixel((width // 2, height // 2))
    corner_pixel = image.getpixel((5, 5))

    assert center_pixel == (0, 0, 0)
    assert corner_pixel == (255, 255, 255)