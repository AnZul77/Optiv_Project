
from pathlib import Path
from typing import Mapping, Optional, Sequence

from pdf2image import convert_from_path
from pypdf import PdfReader, PdfWriter

from .image_redactor import redact_image


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

    Pages are rendered to images, redacted, and rebuilt into a PDF.
    The resulting PDF metadata is then cleared.

    Args:
        source: Path to the original PDF.
        destination: Path where the redacted PDF will be saved.
        page_boxes: Mapping of 1-based page numbers to redaction boxes.
        dpi: Rendering resolution. Must be at least 72.
        padding: Extra pixels around each redaction box.
        poppler_path: Optional path to the Poppler binaries.

    Returns:
        Path to the generated redacted PDF.
    """
    source = Path(source)
    destination = Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError(
            "Source and destination must be different files."
        )

    if not source.is_file():
        raise FileNotFoundError(f"Source PDF not found: {source}")

    if dpi < 72:
        raise ValueError("DPI must be at least 72.")

    if padding < 0:
        raise ValueError("Padding cannot be negative.")

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

    # Rewrite the PDF with cleared document metadata.
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
