"""
Metadata Extractor and Sanitizer
Person 1: Lead Architect (with Person 4: Security Policy)
Extracts and sanitizes document properties, author names, revision histories,
comments, and hidden content channels across PDF, DOCX, and PPTX formats.
"""

from __future__ import annotations
import os
import io
from typing import Dict, List, Optional, Any
from datetime import datetime


class MetadataExtractor:
    """
    Extracts structural metadata, author identity, revisions, and hidden channels from documents.
    """

    @staticmethod
    def extract_from_pdf(file_path: str) -> Dict[str, Any]:
        """Extract metadata from PDF document properties and catalog."""
        try:
            import fitz  # PyMuPDF
            doc = fitz.open(file_path)
            meta = doc.metadata or {}
            
            # Count annotations across all pages
            annot_count = sum(len(list(doc[i].annots())) for i in range(len(doc)))
            
            res = {
                "format": "pdf",
                "title": meta.get("title", ""),
                "author": meta.get("author", ""),
                "subject": meta.get("subject", ""),
                "keywords": meta.get("keywords", ""),
                "creator": meta.get("creator", ""),
                "producer": meta.get("producer", ""),
                "creation_date": meta.get("creationDate", ""),
                "mod_date": meta.get("modDate", ""),
                "page_count": len(doc),
                "is_encrypted": bool(getattr(doc, "needs_pass", getattr(doc, "is_encrypted", False))),
                "annotation_count": annot_count,
                "has_annotations": annot_count > 0,
            }
            doc.close()
            return res
        except Exception as e:
            return {"format": "pdf", "error": str(e)}

    @staticmethod
    def extract_from_docx(file_path: str) -> Dict[str, Any]:
        """Extract metadata from DOCX core and extended properties."""
        try:
            from docx import Document
            doc = Document(file_path)
            core = doc.core_properties

            return {
                "format": "docx",
                "title": core.title or "",
                "author": core.author or "",
                "last_modified_by": core.last_modified_by or "",
                "subject": core.subject or "",
                "comments": core.comments or "",
                "created": core.created.isoformat() if core.created else "",
                "modified": core.modified.isoformat() if core.modified else "",
                "last_printed": core.last_printed.isoformat() if core.last_printed else "",
                "revision": core.revision,
                "category": core.category or "",
                "content_status": core.content_status or "",
                "paragraph_count": len(doc.paragraphs),
                "table_count": len(doc.tables),
            }
        except Exception as e:
            return {"format": "docx", "error": str(e)}

    @staticmethod
    def extract_from_pptx(file_path: str) -> Dict[str, Any]:
        """Extract metadata from PPTX core properties, slide notes, and hidden slides."""
        try:
            from pptx import Presentation
            prs = Presentation(file_path)
            core = prs.core_properties

            hidden_slides = sum(1 for s in prs.slides if s._element.get("show") == "0")
            notes_count = sum(
                1 for s in prs.slides
                if s.has_notes_slide and s.notes_slide.notes_text_frame and s.notes_slide.notes_text_frame.text.strip()
            )

            return {
                "format": "pptx",
                "title": core.title or "",
                "author": core.author or "",
                "last_modified_by": core.last_modified_by or "",
                "subject": core.subject or "",
                "created": core.created.isoformat() if core.created else "",
                "modified": core.modified.isoformat() if core.modified else "",
                "slide_count": len(prs.slides),
                "hidden_slide_count": hidden_slides,
                "slides_with_notes_count": notes_count,
                "has_hidden_slides": hidden_slides > 0,
                "has_speaker_notes": notes_count > 0,
            }
        except Exception as e:
            return {"format": "pptx", "error": str(e)}

    @staticmethod
    def extract_metadata(file_path: str) -> Dict[str, Any]:
        """Universal metadata extraction based on file extension."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".pdf":
            return MetadataExtractor.extract_from_pdf(file_path)
        elif ext == ".docx":
            return MetadataExtractor.extract_from_docx(file_path)
        elif ext == ".pptx":
            return MetadataExtractor.extract_from_pptx(file_path)
        return {"error": f"Unsupported format: {ext}"}


class MetadataSanitizer:
    """
    Sanitizes and strips personal metadata (author, last modified by, comments)
    before documents pass through the sanitization stage.
    """

    @staticmethod
    def sanitize_docx_properties(file_path: str, output_path: str) -> bool:
        """Strip author, last_modified_by, and sensitive metadata from DOCX file."""
        try:
            from docx import Document
            doc = Document(file_path)
            core = doc.core_properties
            core.author = "[REDACTED]"
            core.last_modified_by = "[REDACTED]"
            core.keywords = ""
            core.comments = ""
            doc.save(output_path)
            return True
        except Exception:
            return False

    @staticmethod
    def sanitize_pptx_properties(file_path: str, output_path: str) -> bool:
        """Strip author and personal metadata from PPTX presentation."""
        try:
            from pptx import Presentation
            prs = Presentation(file_path)
            core = prs.core_properties
            core.author = "[REDACTED]"
            core.last_modified_by = "[REDACTED]"
            core.comments = ""
            prs.save(output_path)
            return True
        except Exception:
            return False

    @staticmethod
    def sanitize_pdf_properties(file_path: str, output_path: str) -> bool:
        """Strip author, creator, and producer metadata from PDF document."""
        try:
            import fitz
            doc = fitz.open(file_path)
            doc.set_metadata({
                "title": doc.metadata.get("title", ""),
                "author": "[REDACTED]",
                "creator": "[REDACTED]",
                "producer": "[REDACTED]",
                "subject": "",
                "keywords": "",
            })
            doc.save(output_path)
            doc.close()
            return True
        except Exception:
            return False