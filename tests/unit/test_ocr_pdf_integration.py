
from reportlab.pdfgen import canvas
from pdf2image import convert_from_path

from src.ocr.engine import OCREngine
from src.sanitization.pdf_redactor import redact_scanned_pdf
from src.ocr.residual_scan import scan_residual


POPPLER_PATH = r"C:\poppler-26.09.0\Library\bin"


def test_ocr_to_pdf_redaction_and_residual_scan(tmp_path):
    input_pdf = tmp_path / "synthetic_input.pdf"
    output_pdf = tmp_path / "synthetic_redacted.pdf"

    # Synthetic test document only.
    pdf = canvas.Canvas(str(input_pdf), pagesize=(500, 200))
    pdf.setFont("Helvetica", 18)
    pdf.drawString(40, 100, "Test ID: 483-29-1047")
    pdf.save()

    original_pages = convert_from_path(
        str(input_pdf), dpi=220, poppler_path=POPPLER_PATH
    )
    engine = OCREngine()

    ocr_result = engine.extract(original_pages[0], page=1)
    regions = ocr_result["words"]

    # Do not claim a successful integration if OCR cannot locate text.
    assert regions, "OCR detected no text in the synthetic PDF"

    target = [
        region["bbox"]
        for region in regions
        if "483-29-1047" in region["word"]
    ]

    assert target, (
        "OCR did not recognize the synthetic test ID as one region. "
        "Inspect OCR output and adjust this test to the actual region output."
    )

    redact_scanned_pdf(
        input_pdf,
        output_pdf,
        {1: target},
        dpi=220,
        padding=4,
        poppler_path=POPPLER_PATH,
    )

    redacted_pages = convert_from_path(
        str(output_pdf), dpi=220, poppler_path=POPPLER_PATH
    )

    # The redacted region's center should be black.
    image = redacted_pages[0].convert("RGB")
    x0, y0, x1, y1 = target[0]
    px = int(((x0 + x1) / 2) * image.width)
    py = int(((y0 + y1) / 2) * image.height)
    assert image.getpixel((px, py)) == (0, 0, 0)

    residual = scan_residual(redacted_pages[0], page=1, engine=engine)

    assert residual["needs_policy_verification"] is True

    # Residual OCR is evidence, not proof that the document is safe.
    assert residual["recommended_status"] in {"REVIEW_OR_BLOCK", "VERIFY"}