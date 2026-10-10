"""
Burned PDF Redactor
Person 2: OCR & Vision Lead
Roadmap: Day 10 - Reconstruct sanitized PDFs with opaque burned boxes

Renders PDF pages to images, permanently burns opaque redaction boxes over sensitive
pixel regions, and reconstructs a sanitized, metadata-stripped PDF.
Uses PyMuPDF (fitz) for native, high-performance rendering without requiring external Poppler binaries.
"""

from __future__ import annotations
import io
from pathlib import Path
from typing import Mapping, Optional, Sequence, List

from PIL import Image
from pypdf import PdfReader, PdfWriter

from .image_redactor import redact_image


def render_pdf_to_images(
    source: str | Path,
    dpi: int = 200,
    poppler_path: Optional[str] = None
) -> List[Image.Image]:
    """
    Renders PDF pages to PIL Images.
    Uses PyMuPDF for native rendering without external dependencies,
    with an optional fallback to pdf2image if available.
    """
    # 1. Primary engine: PyMuPDF (fitz)
    try:
        import pymupdf as fitz
        doc = fitz.open(str(source))
        pages = []
        zoom = dpi / 72.0
        mat = fitz.Matrix(zoom, zoom)
        for page in doc:
            pix = page.get_pixmap(matrix=mat)
            img = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
            pages.append(img)
        doc.close()
        if pages:
            return pages
    except ImportError:
        pass

    # 2. Secondary fallback: pdf2image (requires Poppler)
    try:
        from pdf2image import convert_from_path
        return convert_from_path(
            str(source),
            dpi=dpi,
            poppler_path=poppler_path,
        )
    except ImportError:
        raise ImportError(
            "Neither PyMuPDF ('pymupdf') nor 'pdf2image' could be loaded to render PDF pages."
        )


def redact_scanned_pdf(
    source: str | Path,
    destination: str | Path,
    page_boxes: Mapping[int, Sequence],
    dpi: int = 200,
    padding: int = 0,
    poppler_path: Optional[str] = None,
) -> Path:
    """
    Redact specified regions from a scanned PDF.

    Pages are rendered to images, permanently redacted at the pixel level,
    and rebuilt into a fresh PDF with cleared document metadata.

    Args:
        source: Path to the original PDF.
        destination: Path where the redacted PDF will be saved.
        page_boxes: Mapping of 1-based page numbers to normalized redaction boxes [[x0, y0, x1, y1]].
        dpi: Rendering resolution. Must be at least 72.
        padding: Extra pixels around each redaction box.
        poppler_path: Optional path to Poppler binaries (if using pdf2image).

    Returns:
        Path to the generated redacted PDF.
    """
    source = Path(source)
    destination = Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must be different files.")

    if not source.is_file():
        raise FileNotFoundError(f"Source PDF not found: {source}")

    if dpi < 72:
        raise ValueError("DPI must be at least 72.")

    if padding < 0:
        raise ValueError("Padding cannot be negative.")

    destination.parent.mkdir(parents=True, exist_ok=True)

    pages = render_pdf_to_images(
        source,
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

    # Reconstruct PDF from pixel-burned images
    first_page.save(
        str(destination),
        format="PDF",
        save_all=True,
        append_images=remaining_pages,
        resolution=dpi,
    )

    # Rewrite the PDF with cleared document metadata
    reader = PdfReader(str(destination))
    writer = PdfWriter()
    writer.append_pages_from_reader(reader)

    writer.add_metadata(
        {
            "/Title": "",
            "/Author": "",
            "/Subject": "",
            "/Creator": "",
            "/Producer": "",
        }
    )

    with destination.open("wb") as output_file:
        writer.write(output_file)

    return destination
