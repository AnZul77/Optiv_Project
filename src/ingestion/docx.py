"""
DOCX Extractor
Person 1: Lead Architect
Handles DOCX extraction including tables with header context inheritance,
XML text boxes (w:txbxContent), embedded images/screenshots, and structural metadata.
Roadmap: Day 3 - DOCX Extraction (38 screenshots & 16 tables)
"""

from __future__ import annotations
import os
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from docx import Document as DocxDocument
from docx.table import Table
from docx.text.paragraph import Paragraph
from docx.oxml import OxmlElement

from ..schema.document import (
    CanonicalDocument,
    ExtractedPage,
    ExtractedBlock,
    ExtractedImage,
    ExtractedTable,
    TableCell,
    PipelineMetadata,
    ExtractionResult,
)


class DOCXExtractor:
    """
    Enterprise DOCX extraction handler that supports:
    - Structured paragraphs and headings
    - Table extraction with column header context inheritance
    - Embedded screenshot / image extraction from document relationships
    - XML text boxes (w:txbxContent)
    - OpenXML page break detection (w:br[@w:type="page"] and w:lastRenderedPageBreak)
    """

    def __init__(self, ocr_engine=None):
        """
        Args:
            ocr_engine: Optional OCR engine adapter (from Person 2) for embedded screenshots.
        """
        self.ocr_engine = ocr_engine

    def extract(
        self,
        file_path: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[CanonicalDocument, PipelineMetadata]:
        """
        Extract content from a DOCX file.
        
        Args:
            file_path: Path to the DOCX file.
            metadata: Additional metadata dict.
            
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
            extractor_version="1.0.0-docx",
            ocr_engine="python-docx"
        )

        doc = DocxDocument(file_path)

        # 1. Parse paragraphs with page break tracking
        pages_blocks: Dict[int, List[ExtractedBlock]] = {1: []}
        current_page = 1

        for p_idx, para in enumerate(doc.paragraphs):
            text = para.text.strip()
            
            # Check for explicit page break in runs
            has_page_break = False
            for run in para.runs:
                # Check for w:br type="page" or lastRenderedPageBreak
                if any(br.get("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}type") == "page"
                       for br in run._element.xpath(".//w:br")):
                    has_page_break = True
                    break
                if run._element.xpath(".//w:lastRenderedPageBreak"):
                    has_page_break = True
                    break

            if has_page_break and pages_blocks[current_page]:
                current_page += 1
                pages_blocks[current_page] = []

            if text:
                block_type = "heading" if para.style and para.style.name.startswith("Heading") else "paragraph"
                pages_blocks[current_page].append(ExtractedBlock(
                    block_id=f"docx_p{current_page}_para_{p_idx}",
                    page=current_page,
                    block_type=block_type,
                    text=text,
                    style_name=para.style.name if para.style else None
                ))

        # 2. Extract XML Text Boxes (w:txbxContent)
        try:
            txbx_elements = doc.element.xpath(".//w:txbxContent")
            for t_idx, txbx in enumerate(txbx_elements):
                # Extract all text inside text box paragraphs
                tb_paragraphs = txbx.xpath(".//w:p")
                tb_text_parts = []
                for p_elem in tb_paragraphs:
                    p_text = "".join(p_elem.itertext()).strip()
                    if p_text:
                        tb_text_parts.append(p_text)
                
                full_tb_text = "\n".join(tb_text_parts).strip()
                if full_tb_text:
                    # Append to current page
                    pages_blocks[current_page].append(ExtractedBlock(
                        block_id=f"docx_textbox_{t_idx}",
                        page=current_page,
                        block_type="textbox",
                        text=full_tb_text,
                        metadata={"is_text_box": True}
                    ))
        except Exception as txbx_err:
            pipeline_meta.warnings.append(f"Text box extraction warning: {txbx_err}")

        # 3. Extract Tables with Column Header Context Inheritance
        extracted_tables = self._extract_tables(doc, page_num=current_page)

        # 4. Extract Embedded Images / Screenshots
        extracted_images = self._extract_images(doc, page_num=current_page, pipeline_meta=pipeline_meta)

        # Construct CanonicalDocument
        total_pages = max(1, current_page)
        canonical_doc = CanonicalDocument(
            doc_id=doc_id,
            source_path=file_path,
            filename=filename,
            file_type=".docx",
            pages=total_pages,
            metadata={
                "table_count": len(extracted_tables),
                "image_count": len(extracted_images),
            }
        )

        for p_num in range(1, total_pages + 1):
            blocks = pages_blocks.get(p_num, [])
            native_text = "\n\n".join(b.text for b in blocks if b.text)
            
            page_obj = ExtractedPage(
                page_num=p_num,
                native_text=native_text,
                has_native_text=bool(native_text),
                is_scanned=False,
                ocr_confidence=1.0,
                blocks=blocks
            )
            canonical_doc.add_page(page_obj)

        # Attach tables to the respective pages (default to page 1 or current)
        for tbl in extracted_tables:
            target_p = min(tbl.page, total_pages)
            canonical_doc.pages_dict[target_p].tables.append(tbl)

        # Attach images to the respective pages
        for img in extracted_images:
            target_p = min(img.page, total_pages)
            canonical_doc.pages_dict[target_p].images.append(img)

        pipeline_meta.extraction_time = time.time() - start_time
        return canonical_doc, pipeline_meta

    def _extract_tables(self, doc: DocxDocument, page_num: int) -> List[ExtractedTable]:
        """
        Extract tables with cell-level column header inheritance.
        Header context resolves column meaning for cell values (e.g. Employee ID, SSN).
        """
        tables = []
        for t_idx, table in enumerate(doc.tables):
            if not table.rows:
                continue

            # First row considered header row
            header_row = table.rows[0]
            headers = [cell.text.strip() for cell in header_row.cells]

            extracted_rows: List[List[TableCell]] = []

            for r_idx, row in enumerate(table.rows[1:], start=1):
                cell_objs = []
                for c_idx, cell in enumerate(row.cells):
                    val = cell.text.strip()
                    hdr_name = headers[c_idx] if c_idx < len(headers) else f"Column_{c_idx+1}"
                    cell_objs.append(TableCell(
                        row_idx=r_idx,
                        col_idx=c_idx,
                        text=val,
                        header_name=hdr_name
                    ))
                extracted_rows.append(cell_objs)

            ext_table = ExtractedTable(
                table_index=t_idx + 1,
                page=page_num,
                headers=headers,
                rows=extracted_rows,
                metadata={"row_count": len(table.rows), "col_count": len(headers)}
            )
            ext_table.raw_markdown = ext_table.to_markdown()
            tables.append(ext_table)

        return tables

    def _extract_images(
        self,
        doc: DocxDocument,
        page_num: int,
        pipeline_meta: PipelineMetadata
    ) -> List[ExtractedImage]:
        """
        Extract all embedded images and screenshots from relationships.
        Enables Person 2's OCR engine to detect visual PII within OneTrust screenshots.
        """
        images = []
        rel_idx = 0

        for rel_id, rel in doc.part.rels.items():
            if "image" in rel.target_ref.lower() or rel.target_ref.lower().endswith(
                (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".webp")
            ):
                try:
                    blob = rel.target_part.blob
                    ext = rel.target_ref.split(".")[-1].lower() if "." in rel.target_ref else "png"
                    
                    # Distinguish screenshot based on heuristics / dimensions
                    is_screenshot = len(blob) > 20480  # screenshots are typically > 20KB
                    
                    ocr_text = ""
                    ocr_conf = 0.0

                    # Run OCR on embedded screenshot if engine adapter provided
                    if self.ocr_engine:
                        try:
                            ocr_res = self.ocr_engine.extract_text(blob)
                            if isinstance(ocr_res, dict):
                                ocr_text = ocr_res.get("text", "")
                                ocr_conf = ocr_res.get("confidence", 0.0)
                            elif isinstance(ocr_res, str):
                                ocr_text = ocr_res
                                ocr_conf = 0.95
                        except Exception as ocr_err:
                            pipeline_meta.warnings.append(f"OCR failed for DOCX image {rel_id}: {ocr_err}")

                    images.append(ExtractedImage(
                        image_id=f"docx_img_{rel_idx}_{rel_id}",
                        page=page_num,
                        image_bytes=blob,
                        image_format=ext,
                        relationship_id=rel_id,
                        is_screenshot=is_screenshot,
                        ocr_text=ocr_text,
                        ocr_confidence=ocr_conf,
                        metadata={"target_ref": rel.target_ref, "size_bytes": len(blob)}
                    ))
                    rel_idx += 1
                except Exception as img_err:
                    pipeline_meta.warnings.append(f"Failed to read image relation {rel_id}: {img_err}")

        return images