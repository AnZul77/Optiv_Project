
"""Raster-based redaction for scanned PDFs."""

from pathlib import Path
from typing import Dict, List, Sequence, Union

from PIL import Image
from pdf2image import convert_from_path

from src.sanitization.image_redactor import redact_image


def redact_scanned_pdf(
    input_pdf: Union[str, Path],
    output_pdf: Union[str, Path],
    page_boxes: Dict[int, List[Sequence[float]]],
    dpi: int = 220,
    padding: int = 4,
    poppler_path: str = None,
) -> Path:
    """
    Render, redact, and rebuild a scanned PDF.

    page_boxes maps 1-based page numbers to normalized [x0,y0,x1,y1] boxes.
    This function does not perform PII detection or final safety verification.
    """
    source = Path(input_pdf)
    destination = Path(output_pdf)

    if not source.is_file():
        raise FileNotFoundError(f"Input PDF not found: {source}")

    if source.resolve() == destination.resolve():
        raise ValueError("Input and output PDF paths must be different.")

    if dpi < 72:
        raise ValueError("DPI must be at least 72.")

    destination.parent.mkdir(parents=True, exist_ok=True)

    pages = convert_from_path(
        str(source),
        dpi=dpi,
        poppler_path=poppler_path,
    )

    if not pages:
        raise ValueError("PDF produced no rendered pages.")

    sanitized_pages = []
    for page_number, page_image in enumerate(pages, start=1):
        boxes = page_boxes.get(page_number, [])
        sanitized = redact_image(
            page_image,
            boxes,
            padding=padding,
        )
sanitized_pages.append(sanitized.convert("RGB"))
first_page = sanitized_pages[0]
remaining_pages = sanitized_pages[1:]

    first_page.save(
        str(destination),
        format="PDF",
        save_all=True,
        append_images=remaining_pages,
        resolution=dpi,
    )
    from pypdf import PdfReader, PdfWriter

    reader = PdfReader(str(destination))
    writer = PdfWriter()
    writer.append_pages_from_reader(reader)
    writer.add_metadata({
        "/Title": "",
        "/Author": "",
        "/Subject": "",
        "/Creator": "",
        "/Producer": "",
    })

    with open(destination, "wb") as output_file:
        writer.write(output_file)


    return destination