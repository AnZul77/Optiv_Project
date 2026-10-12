"""
DOCX Embedded Image OCR & Redaction Engine
Detects and redacts PII within embedded images inside DOCX documents.
"""

from __future__ import annotations

import io
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from docx import Document
from PIL import Image

from src.ocr.regions import extract_word_level_pii_boxes, find_pii_spans_in_text
from src.sanitization.docx_reconstructor import DOCXReconstructor
from src.sanitization.image_redactor import redact_image_bytes
from src.security.integrity import DocumentIntegrityGuard


@dataclass
class EmbeddedImageInfo:
    """Metadata and raw payload for an image embedded in a DOCX file."""

    rel_id: str
    target_ref: str
    filename: str
    part_name: str
    content_type: str
    blob: bytes
    is_raster: bool
    width: Optional[int] = None
    height: Optional[int] = None


@dataclass
class DOCXImageRedactionReport:
    """Summary report detailing the outcome of DOCX image redaction."""

    success: bool
    total_images: int
    scanned_images: int
    redacted_images: int
    total_boxes_redacted: int
    error: Optional[str] = None
    details: List[Dict[str, Any]] = field(default_factory=list)


class DOCXImageRedactor:
    """
    Scans and redacts embedded screenshot and raster images in DOCX documents.

    Workflow:
    1. Extracts all embedded image parts and their relationships via python-docx.
    2. Runs OCR (or uses provided OCR engine / pre-extracted OCR results) to detect PII.
    3. Derives precise normalized bounding boxes for sensitive text spans.
    4. Irreversibly burns black pixels over the detected regions.
    5. Replaces the original images in the DOCX document and validates document integrity.
    """

    def __init__(
        self,
        ocr_engine: Optional[Any] = None,
        padding: int = 4,
    ) -> None:
        """
        Initialize the DOCXImageRedactor.

        Args:
            ocr_engine: Optional OCR engine instance or callable. If None,
                        OCREngine will be instantiated lazily when needed.
            padding: Pixel padding to expand around detected redaction boxes.
        """
        self.ocr_engine = ocr_engine
        self.padding = max(0, padding)

    def extract_images(
        self,
        docx_source: Union[str, Path, Any],
    ) -> List[EmbeddedImageInfo]:
        """
        Extract all embedded images from a DOCX file or open Document object.

        Args:
            docx_source: Path to the DOCX file or an existing python-docx Document object.

        Returns:
            List of EmbeddedImageInfo objects representing images found in the document.
        """
        if hasattr(docx_source, "part") and hasattr(docx_source.part, "rels"):
            doc = docx_source
        else:
            doc = Document(str(docx_source))

        extracted_images: List[EmbeddedImageInfo] = []
        seen_partnames: set[str] = set()

        def _record_part(rel_id: str, target_ref: str, part: Any) -> None:
            if part is None:
                return
            part_name = str(getattr(part, "partname", ""))
            if part_name in seen_partnames:
                return
            # Ignore package metadata thumbnails (e.g. /docProps/thumbnail.jpeg)
            if "docprops" in part_name.lower() or "thumbnail" in part_name.lower():
                return
            seen_partnames.add(part_name)

            content_type = str(getattr(part, "content_type", "")).lower()
            filename = os.path.basename(part_name or target_ref)
            blob = getattr(part, "blob", b"")

            is_raster = False
            width: Optional[int] = None
            height: Optional[int] = None

            if blob:
                try:
                    with Image.open(io.BytesIO(blob)) as pil_img:
                        is_raster = True
                        width, height = pil_img.size
                except Exception:
                    is_raster = False

            extracted_images.append(
                EmbeddedImageInfo(
                    rel_id=rel_id,
                    target_ref=target_ref,
                    filename=filename,
                    part_name=part_name,
                    content_type=content_type,
                    blob=blob,
                    is_raster=is_raster,
                    width=width,
                    height=height,
                )
            )

        # 1. Main document relationships
        for rel_id, rel in doc.part.rels.items():
            reltype = str(getattr(rel, "reltype", "")).lower()
            target_ref = str(getattr(rel, "target_ref", ""))
            if "image" in reltype or "image" in target_ref.lower():
                _record_part(rel_id, target_ref, getattr(rel, "target_part", None))

        # 2. Section headers and footers
        if hasattr(doc, "sections"):
            for section in doc.sections:
                for hf_attr in (
                    "header",
                    "footer",
                    "first_page_header",
                    "first_page_footer",
                    "even_page_header",
                    "even_page_footer",
                ):
                    hf = getattr(section, hf_attr, None)
                    if hf is not None and hasattr(hf, "part") and hasattr(hf.part, "rels"):
                        for rel_id, rel in hf.part.rels.items():
                            reltype = str(getattr(rel, "reltype", "")).lower()
                            target_ref = str(getattr(rel, "target_ref", ""))
                            if "image" in reltype or "image" in target_ref.lower():
                                _record_part(rel_id, target_ref, getattr(rel, "target_part", None))

        # 3. Any additional image parts in package parts
        if hasattr(doc.part, "package") and hasattr(doc.part.package, "parts"):
            for part in doc.part.package.parts:
                content_type = str(getattr(part, "content_type", "")).lower()
                if "image" in content_type:
                    part_name = str(getattr(part, "partname", ""))
                    if part_name not in seen_partnames:
                        _record_part("", os.path.basename(part_name), part)

        return extracted_images

    def detect_pii_boxes(
        self,
        image_bytes: bytes,
        ocr_results: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None,
        img_dimensions: Optional[Tuple[int, int]] = None,
    ) -> List[List[float]]:
        """
        Detect sensitive PII bounding boxes within an image payload.

        Args:
            image_bytes: Raw bytes of the image to scan.
            ocr_results: Optional pre-extracted OCR results. If provided, OCR will
                         not be run and these results are parsed directly.
            img_dimensions: Optional (width, height) tuple. If omitted, dimensions
                            are inferred from the image bytes via PIL.

        Returns:
            List of normalized bounding boxes [x0, y0, x1, y1] for sensitive text regions.
        """
        if not image_bytes:
            return []

        # Determine dimensions
        if img_dimensions is not None and img_dimensions[0] > 0 and img_dimensions[1] > 0:
            width, height = img_dimensions
        else:
            try:
                with Image.open(io.BytesIO(image_bytes)) as img:
                    width, height = img.size
            except Exception:
                return []

        # Obtain OCR detections
        if ocr_results is not None:
            raw_ocr = ocr_results
        else:
            if self.ocr_engine is None:
                from src.ocr.engine import OCREngine

                self.ocr_engine = OCREngine()

            if callable(self.ocr_engine):
                raw_ocr = self.ocr_engine(image_bytes)
            elif hasattr(self.ocr_engine, "extract"):
                raw_ocr = self.ocr_engine.extract(image_bytes)
            elif hasattr(self.ocr_engine, "readtext"):
                raw_ocr = self.ocr_engine.readtext(image_bytes)
            else:
                raise TypeError(
                    f"Unsupported OCR engine type: {type(self.ocr_engine)}. "
                    "Expected callable or object with .extract() or .readtext()."
                )

        # Convert OCR detections and PII spans into normalized bounding boxes
        return extract_word_level_pii_boxes(raw_ocr, width, height)

    def redact_image(
        self,
        image_bytes: bytes,
        boxes: Sequence[Sequence[float]],
        padding: Optional[int] = None,
    ) -> bytes:
        """
        Burn opaque black redaction boxes over specified normalized coordinates.

        Args:
            image_bytes: Original image bytes.
            boxes: Sequence of normalized bounding boxes [x0, y0, x1, y1].
            padding: Optional padding in pixels. Defaults to self.padding.

        Returns:
            Redacted image bytes in PNG format, or original bytes if boxes is empty.
        """
        if not boxes:
            return image_bytes

        pad = self.padding if padding is None else max(0, padding)
        return redact_image_bytes(image_bytes, boxes, padding=pad)

    def redact_docx(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        pre_extracted_ocr: Optional[Dict[str, Any]] = None,
        preserve_integrity: bool = True,
    ) -> Tuple[bool, Optional[str], DOCXImageRedactionReport]:
        """
        Scan embedded images in a DOCX, redact any detected PII, and reconstruct the document.

        Args:
            input_path: Path to the input DOCX file.
            output_path: Destination path for the sanitized DOCX file.
            pre_extracted_ocr: Mapping of {rel_id / filename / part_name: ocr_results}
                               to avoid running live OCR.
            preserve_integrity: If True, validates reconstructed file via DocumentIntegrityGuard.

        Returns:
            Tuple of (success: bool, error_message: Optional[str], report: DOCXImageRedactionReport).
        """
        input_str = str(input_path)
        output_str = str(output_path)

        if not os.path.exists(input_str):
            report = DOCXImageRedactionReport(
                success=False,
                total_images=0,
                scanned_images=0,
                redacted_images=0,
                total_boxes_redacted=0,
                error=f"Source file not found: {input_str}",
            )
            return False, report.error, report

        try:
            images = self.extract_images(input_str)
        except Exception as exc:
            report = DOCXImageRedactionReport(
                success=False,
                total_images=0,
                scanned_images=0,
                redacted_images=0,
                total_boxes_redacted=0,
                error=f"Failed to extract images from DOCX: {exc}",
            )
            return False, report.error, report

        total_images = len(images)
        scanned_images = 0
        redacted_images = 0
        total_boxes_redacted = 0
        image_replacements: Dict[str, bytes] = {}
        details: List[Dict[str, Any]] = []

        for img in images:
            img_detail: Dict[str, Any] = {
                "rel_id": img.rel_id,
                "target_ref": img.target_ref,
                "filename": img.filename,
                "part_name": img.part_name,
                "content_type": img.content_type,
                "is_raster": img.is_raster,
                "boxes_detected": 0,
                "redacted": False,
            }

            if not img.is_raster:
                img_detail["skipped"] = "Non-raster or unsupported format"
                details.append(img_detail)
                continue

            scanned_images += 1

            # Check if caller supplied pre-extracted OCR results for this image
            ocr_data = None
            if pre_extracted_ocr:
                for lookup_key in (img.rel_id, img.target_ref, img.filename, img.part_name):
                    if lookup_key and lookup_key in pre_extracted_ocr:
                        ocr_data = pre_extracted_ocr[lookup_key]
                        break

            # Detect PII boxes
            try:
                boxes = self.detect_pii_boxes(
                    img.blob,
                    ocr_results=ocr_data,
                    img_dimensions=(img.width, img.height) if img.width and img.height else None,
                )
            except Exception as ocr_err:
                img_detail["ocr_error"] = str(ocr_err)
                details.append(img_detail)
                continue

            if boxes:
                try:
                    redacted_bytes = self.redact_image(img.blob, boxes)
                except Exception as red_err:
                    img_detail["redaction_error"] = str(red_err)
                    details.append(img_detail)
                    continue

                # Register replacement keys
                if img.rel_id:
                    image_replacements[img.rel_id] = redacted_bytes
                if img.target_ref:
                    image_replacements[img.target_ref] = redacted_bytes
                if img.filename:
                    image_replacements[img.filename] = redacted_bytes
                if img.part_name:
                    image_replacements[img.part_name] = redacted_bytes

                redacted_images += 1
                total_boxes_redacted += len(boxes)
                img_detail["boxes_detected"] = len(boxes)
                img_detail["redacted"] = True

            details.append(img_detail)

        # Reconstruct the document with replaced images
        if not image_replacements:
            if os.path.abspath(input_str) != os.path.abspath(output_str):
                os.makedirs(os.path.dirname(os.path.abspath(output_str)), exist_ok=True)
                shutil.copy2(input_str, output_str)

            report = DOCXImageRedactionReport(
                success=True,
                total_images=total_images,
                scanned_images=scanned_images,
                redacted_images=0,
                total_boxes_redacted=0,
                details=details,
            )
            return True, None, report

        success, err = DOCXReconstructor.replace_images_in_document(
            input_path=input_str,
            output_path=output_str,
            image_replacements=image_replacements,
            preserve_integrity=preserve_integrity,
        )

        report = DOCXImageRedactionReport(
            success=success,
            total_images=total_images,
            scanned_images=scanned_images,
            redacted_images=redacted_images if success else 0,
            total_boxes_redacted=total_boxes_redacted if success else 0,
            error=err,
            details=details,
        )

        return success, err, report
