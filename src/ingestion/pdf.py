"""
PDF Extractor
Person 1: Lead Architect
Handles native text PDFs, scanned page rendering for OCR, form fields, and annotation extraction.
Roadmap: Day 2 - PDF Extraction & OCR Benchmarking
"""

from __future__ import annotations
import os
import io
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from ..schema.document import (
    CanonicalDocument,
    ExtractedPage,
    ExtractedBlock,
    ExtractedImage,
    ExtractedTable,
    PipelineMetadata,
    ExtractionResult,
    BoundingBox,
)


class PDFExtractor:
    """
    Multimodal PDF extraction engine supporting:
    - Native text extraction with block/paragraph coordinates
    - Scanned page detection and high-resolution rendering for Person 2 OCR
    - Form fields and PDF annotations (common hidden PII channels)
    - Fallback mechanism across PyMuPDF and pypdf
    """

    def __init__(self, ocr_engine=None, render_dpi: int = 220):
        """
        Args:
            ocr_engine: Optional OCR engine adapter (from Person 2).
            render_dpi: DPI resolution for rendering scanned pages (220-dpi per PRD).
        """
        self.ocr_engine = ocr_engine
        self.render_dpi = render_dpi

    def extract(
        self,
        file_path: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[CanonicalDocument, PipelineMetadata]:
        """
        Extract content from a PDF file.
        
        Args:
            file_path: Path to the PDF file.
            metadata: Additional metadata dictionary.
            
        Returns:
            Tuple of (CanonicalDocument, PipelineMetadata).
        """
        start_time = time.time()
        file_meta = metadata or {}
        doc_id = file_meta.get("doc_id", os.path.basename(file_path))
        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

        pipeline_meta = PipelineMetadata(
            file_size_bytes=file_size,
            extractor_version="1.0.0-pdf"
        )

        try:
            return self._extract_with_fitz(file_path, doc_id, filename, pipeline_meta, start_time)
        except ImportError:
            # Fallback to pypdf if PyMuPDF is unavailable
            return self._extract_with_pypdf(file_path, doc_id, filename, pipeline_meta, start_time)

    def _extract_with_fitz(
        self,
        file_path: str,
        doc_id: str,
        filename: str,
        pipeline_meta: PipelineMetadata,
        start_time: float
    ) -> Tuple[CanonicalDocument, PipelineMetadata]:
        import fitz  # PyMuPDF

        doc = fitz.open(file_path)
        total_pages = len(doc)
        
        canonical_doc = CanonicalDocument(
            doc_id=doc_id,
            source_path=file_path,
            filename=filename,
            file_type=".pdf",
            pages=total_pages,
            metadata={
                "title": doc.metadata.get("title", ""),
                "author": doc.metadata.get("author", ""),
                "creator": doc.metadata.get("creator", ""),
                "creation_date": doc.metadata.get("creationDate", ""),
                "mod_date": doc.metadata.get("modDate", ""),
                "encrypted": bool(getattr(doc, "needs_pass", getattr(doc, "is_encrypted", False))),
            }
        )

        has_any_native_text = False

        for page_idx in range(total_pages):
            page_num = page_idx + 1
            page = doc[page_idx]
            
            extracted_page = ExtractedPage(page_num=page_num)
            
            # 1. Native text extraction by blocks
            page_text_parts = []
            text_blocks = page.get_text("blocks")  # (x0, y0, x1, y1, text, block_no, block_type)
            
            for b_idx, block in enumerate(text_blocks):
                # block_type 0 is text, 1 is image
                if len(block) >= 5 and block[4].strip():
                    x0, y0, x1, y1 = block[0], block[1], block[2], block[3]
                    txt = block[4].strip()
                    page_text_parts.append(txt)
                    
                    extracted_page.blocks.append(ExtractedBlock(
                        block_id=f"p{page_num}_b{b_idx}",
                        page=page_num,
                        block_type="paragraph",
                        text=txt,
                        bbox=[float(x0), float(y0), float(x1), float(y1)]
                    ))

            full_native_text = "\n\n".join(page_text_parts).strip()
            extracted_page.native_text = full_native_text
            extracted_page.has_native_text = bool(full_native_text)
            
            if full_native_text:
                has_any_native_text = True
                extracted_page.ocr_confidence = 1.0
            else:
                extracted_page.is_scanned = True
                extracted_page.ocr_confidence = 0.0

            # 2. Extract embedded images on page
            image_list = page.get_images(full=True)
            for img_idx, img_info in enumerate(image_list):
                xref = img_info[0]
                try:
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]
                    image_ext = base_image["ext"]
                    width = base_image["width"]
                    height = base_image["height"]
                    
                    extracted_page.images.append(ExtractedImage(
                        image_id=f"p{page_num}_img_{img_idx}",
                        page=page_num,
                        image_bytes=image_bytes,
                        image_format=image_ext,
                        width=width,
                        height=height,
                        relationship_id=str(xref)
                    ))
                except Exception as img_err:
                    pipeline_meta.warnings.append(f"Failed to extract image xref {xref} on page {page_num}: {img_err}")

            # 3. For scanned pages or when OCR is enabled, render page to image for Person 2 OCR pipeline
            if not extracted_page.has_native_text or self.ocr_engine is not None:
                # Render page at 220-dpi (zoom = 220 / 72 ≈ 3.05)
                zoom = self.render_dpi / 72.0
                mat = fitz.Matrix(zoom, zoom)
                pix = page.get_pixmap(matrix=mat)
                rendered_png_bytes = pix.tobytes("png")
                
                # Add rendered page image for OCR consumption
                extracted_page.images.append(ExtractedImage(
                    image_id=f"p{page_num}_rendered_fullpage",
                    page=page_num,
                    image_bytes=rendered_png_bytes,
                    image_format="png",
                    width=pix.width,
                    height=pix.height,
                    bbox=[0.0, 0.0, float(page.rect.width), float(page.rect.height)],
                    metadata={"rendered_page": True, "dpi": self.render_dpi}
                ))

                # If OCR engine adapter provided, invoke it
                if self.ocr_engine:
                    try:
                        ocr_res = self.ocr_engine.extract_text(rendered_png_bytes)
                        if isinstance(ocr_res, dict):
                            extracted_page.ocr_text = ocr_res.get("text", "")
                            extracted_page.ocr_confidence = ocr_res.get("confidence", 0.0)
                        elif isinstance(ocr_res, str):
                            extracted_page.ocr_text = ocr_res
                            extracted_page.ocr_confidence = 0.95
                    except Exception as ocr_err:
                        pipeline_meta.warnings.append(f"OCR invocation failed on page {page_num}: {ocr_err}")

            # 4. Extract annotations (links, comments, form fields)
            try:
                for annot in page.annots():
                    info = annot.info
                    annot_text = info.get("content", "").strip()
                    if annot_text:
                        rect = annot.rect
                        extracted_page.blocks.append(ExtractedBlock(
                            block_id=f"p{page_num}_annot_{annot.xref}",
                            page=page_num,
                            block_type="annotation",
                            text=annot_text,
                            bbox=[float(rect.x0), float(rect.y0), float(rect.x1), float(rect.y1)],
                            metadata={"subject": info.get("subject", ""), "title": info.get("title", "")}
                        ))
            except Exception:
                pass

            canonical_doc.add_page(extracted_page)

        doc.close()

        pipeline_meta.extraction_time = time.time() - start_time
        pipeline_meta.ocr_engine = "fitz_native" if has_any_native_text else "scanned_rendered"
        return canonical_doc, pipeline_meta

    def _extract_with_pypdf(
        self,
        file_path: str,
        doc_id: str,
        filename: str,
        pipeline_meta: PipelineMetadata,
        start_time: float
    ) -> Tuple[CanonicalDocument, PipelineMetadata]:
        import pypdf

        reader = pypdf.PdfReader(file_path)
        total_pages = len(reader.pages)

        canonical_doc = CanonicalDocument(
            doc_id=doc_id,
            source_path=file_path,
            filename=filename,
            file_type=".pdf",
            pages=total_pages
        )

        for page_idx, page in enumerate(reader.pages):
            page_num = page_idx + 1
            text = page.extract_text() or ""
            
            extracted_page = ExtractedPage(
                page_num=page_num,
                native_text=text.strip(),
                has_native_text=bool(text.strip()),
                is_scanned=not bool(text.strip()),
                ocr_confidence=1.0 if text.strip() else 0.0
            )
            
            if text.strip():
                extracted_page.blocks.append(ExtractedBlock(
                    block_id=f"p{page_num}_b0",
                    page=page_num,
                    block_type="paragraph",
                    text=text.strip()
                ))

            # Extract embedded images via pypdf
            for img_idx, img_file in enumerate(page.images):
                extracted_page.images.append(ExtractedImage(
                    image_id=f"p{page_num}_img_{img_idx}",
                    page=page_num,
                    image_bytes=img_file.data,
                    image_format=img_file.name.split(".")[-1].lower() if "." in img_file.name else "png",
                    relationship_id=img_file.name
                ))

            canonical_doc.add_page(extracted_page)

        pipeline_meta.extraction_time = time.time() - start_time
        pipeline_meta.ocr_engine = "pypdf_fallback"
        return canonical_doc, pipeline_meta