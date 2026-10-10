"""
DOCX Document Reconstructor
Person 1: Lead Architect (with Person 2: Image Redaction & Person 4: Text Redaction)
Roadmap: Days 9 & 10 - Native Text Replacement and Embedded Image Swapping

Reconstructs native DOCX documents after PII redaction:
- Performs native text replacement across paragraphs, table cells, and text boxes
  while preserving fonts, bold/italic formatting, and styles.
- Replaces embedded screenshot images in OpenXML media relationships with pixel-burned versions.
- Enforces post-reconstruction integrity validation.
"""

from __future__ import annotations
import os
import shutil
from typing import Dict, List, Optional, Tuple, Any
from docx import Document
from docx.text.paragraph import Paragraph

from ..security.integrity import DocumentIntegrityGuard, IntegrityCheckResult


class DOCXReconstructor:
    """
    Reconstructs sanitized DOCX documents preserving structure and formatting.
    """

    @staticmethod
    def replace_text_in_document(
        input_path: str,
        output_path: str,
        replacements: Dict[str, str],
        preserve_integrity: bool = True
    ) -> Tuple[bool, Optional[str]]:
        """
        Replace target text spans with redaction tokens across paragraphs, tables, and text boxes.
        
        Args:
            input_path: Path to the source DOCX.
            output_path: Destination path for the reconstructed DOCX.
            replacements: Mapping of {target_text: replacement_token}.
            preserve_integrity: If True, validates reconstructed file before returning.
            
        Returns:
            Tuple of (success: bool, error_message: Optional[str]).
        """
        if not os.path.exists(input_path):
            return False, f"Source file not found: {input_path}"

        # Filter and sort targets by length descending for greedy replacement
        valid_targets = [k for k in replacements.keys() if k and k.strip()]
        if not valid_targets:
            shutil.copy2(input_path, output_path)
            return True, None

        import re
        sorted_targets = sorted(valid_targets, key=len, reverse=True)
        regex_pattern = re.compile("|".join(re.escape(k) for k in sorted_targets))

        def _sub_func(match: re.Match) -> str:
            return replacements.get(match.group(0), match.group(0))

        try:
            doc = Document(input_path)

            # 1. Replace in body paragraphs
            for para in doc.paragraphs:
                DOCXReconstructor._replace_in_paragraph_fast(para, regex_pattern, _sub_func)

            # 2. Replace in tables (including nested cells)
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        for p in cell.paragraphs:
                            DOCXReconstructor._replace_in_paragraph_fast(p, regex_pattern, _sub_func)

            # 3. Replace in XML text boxes (w:txbxContent)
            try:
                txbx_elements = doc.element.xpath(".//w:txbxContent//w:p")
                for p_elem in txbx_elements:
                    para = Paragraph(p_elem, doc)
                    DOCXReconstructor._replace_in_paragraph_fast(para, regex_pattern, _sub_func)
            except Exception:
                pass

            # Save the reconstructed document
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            doc.save(output_path)

            # 4. Post-reconstruction integrity check
            if preserve_integrity:
                check = DocumentIntegrityGuard.verify_document(output_path)
                if not check.is_valid:
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    return False, f"Reconstructed document failed integrity check: {check.error}"

            return True, None

        except Exception as e:
            return False, f"Failed to reconstruct DOCX: {e}"

    @staticmethod
    def _replace_in_paragraph_fast(paragraph: Paragraph, pattern: Any, sub_func: Any) -> None:
        """
        Fast regex-based replacement within a paragraph while preserving styling.
        """
        if not pattern.search(paragraph.text):
            return

        # Check if individual runs contain matches
        for run in paragraph.runs:
            if pattern.search(run.text):
                run.text = pattern.sub(sub_func, run.text)

        # Cross-run check: if paragraph still contains matches that crossed run boundaries
        if pattern.search(paragraph.text):
            full_text = pattern.sub(sub_func, paragraph.text)
            if paragraph.runs:
                paragraph.runs[0].text = full_text
                for r in paragraph.runs[1:]:
                    r.text = ""
            else:
                paragraph.text = full_text

    @staticmethod
    def _replace_in_paragraph(paragraph: Paragraph, replacements: Dict[str, str]) -> None:
        """Legacy fallback replacement helper."""
        valid_targets = [k for k in replacements.keys() if k and k.strip()]
        if not valid_targets:
            return
        import re
        sorted_targets = sorted(valid_targets, key=len, reverse=True)
        pat = re.compile("|".join(re.escape(k) for k in sorted_targets))
        DOCXReconstructor._replace_in_paragraph_fast(paragraph, pat, lambda m: replacements.get(m.group(0), m.group(0)))


    @staticmethod
    def replace_images_in_document(
        input_path: str,
        output_path: str,
        image_replacements: Dict[str, bytes],
        preserve_integrity: bool = True
    ) -> Tuple[bool, Optional[str]]:
        """
        Replace embedded screenshot images with redacted/pixel-burned image bytes.
        
        Args:
            input_path: Path to the source DOCX.
            output_path: Destination path for the reconstructed DOCX.
            image_replacements: Mapping of {relationship_id_or_ref: replacement_image_bytes}.
            preserve_integrity: If True, validates reconstructed file before returning.
            
        Returns:
            Tuple of (success: bool, error_message: Optional[str]).
        """
        if not os.path.exists(input_path):
            return False, f"Source file not found: {input_path}"

        if not image_replacements:
            shutil.copy2(input_path, output_path)
            return True, None

        try:
            doc = Document(input_path)

            replaced_count = 0
            for rel_id, rel in doc.part.rels.items():
                # Match by relationship_id or target_ref
                new_bytes = None
                if rel_id in image_replacements:
                    new_bytes = image_replacements[rel_id]
                elif rel.target_ref in image_replacements:
                    new_bytes = image_replacements[rel.target_ref]
                else:
                    # Also match by basename (e.g. image1.png)
                    base_ref = os.path.basename(rel.target_ref)
                    if base_ref in image_replacements:
                        new_bytes = image_replacements[base_ref]

                if new_bytes is not None:
                    # Overwrite underlying image part blob
                    try:
                        rel.target_part._blob = new_bytes
                        replaced_count += 1
                    except Exception as blob_err:
                        return False, f"Failed updating image blob for relation {rel_id}: {blob_err}"

            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            doc.save(output_path)

            if preserve_integrity:
                check = DocumentIntegrityGuard.verify_document(output_path)
                if not check.is_valid:
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    return False, f"Reconstructed DOCX failed integrity check: {check.error}"

            return True, None

        except Exception as e:
            return False, f"Failed to replace images in DOCX: {e}"
