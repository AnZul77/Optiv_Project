import pymupdf as fitz
from src.ocr.engine import OCREngine
from src.sanitization.pdf_redactor import redact_scanned_pdf, render_pdf_to_images
from src.ocr.residual_scan import scan_residual


def test_ocr_to_pdf_redaction_and_residual_scan(tmp_path):
    input_pdf = tmp_path / "synthetic_input.pdf"
    output_pdf = tmp_path / "synthetic_redacted.pdf"

    # Synthetic test document created natively via PyMuPDF
    doc = fitz.open()
    page = doc.new_page(width=500, height=200)
    page.insert_text((40, 100), "Test ID: 483-29-1047", fontsize=18)
    doc.save(str(input_pdf))
    doc.close()

    original_pages = render_pdf_to_images(input_pdf, dpi=220)
    engine = OCREngine()

    ocr_result = engine.extract(original_pages[0], page=1)
    regions = ocr_result["words"]

    # Assert OCR detected text in the synthetic PDF
    assert regions, "OCR detected no text in the synthetic PDF"

    target = [
        region["bbox"]
        for region in regions
        if "483-29-1047" in region["word"] or "483" in region["word"] or "1047" in region["word"]
    ]

    assert target, (
        f"OCR did not recognize the synthetic test ID. Recognized words: {[r['word'] for r in regions]}"
    )

    redact_scanned_pdf(
        input_pdf,
        output_pdf,
        {1: target},
        dpi=220,
        padding=4,
    )

    redacted_pages = render_pdf_to_images(output_pdf, dpi=220)

    # The redacted region's center should be black.
    image = redacted_pages[0].convert("RGB")
    x0, y0, x1, y1 = target[0]
    px = int(((x0 + x1) / 2) * image.width)
    py = int(((y0 + y1) / 2) * image.height)
    assert image.getpixel((px, py)) == (0, 0, 0)

    residual = scan_residual(redacted_pages[0], page=1, engine=engine)

    assert residual["needs_policy_verification"] is True
    assert residual["recommended_status"] in {"REVIEW_OR_BLOCK", "VERIFY"}