"""
Sanitized Document Integrity Guard
Person 1: Lead Architect (with Person 4: Security Policy)
Roadmap: Day 11 - Sanitized File Open-and-Read Integrity Check

Validates that any reconstructed or sanitized document is structurally sound,
has uncorrupted XML parts, and can be cleanly opened by standard parsers.
Enforces fail-closed: If a sanitized file is corrupted, it is BLOCKED from downstream delivery.
"""

from __future__ import annotations
import os
import zipfile
from dataclasses import dataclass
from typing import Tuple, List, Optional


@dataclass
class IntegrityCheckResult:
    """Outcome of document integrity verification."""
    is_valid: bool
    file_path: str
    file_type: str
    error: Optional[str] = None
    warnings: List[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


class DocumentIntegrityGuard:
    """
    Automated open-and-read integrity verifier for post-redaction documents.
    Prevents corrupt or broken files from passing to LLM ingestion or user download.
    """

    @staticmethod
    def verify_document(file_path: str) -> IntegrityCheckResult:
        """
        Verify that a document can be opened and parsed without structural or XML corruption.
        
        Args:
            file_path: Absolute or relative path to the sanitized document.
            
        Returns:
            IntegrityCheckResult indicating PASS or FAIL.
        """
        if not os.path.exists(file_path):
            return IntegrityCheckResult(
                is_valid=False,
                file_path=file_path,
                file_type="unknown",
                error=f"File not found: {file_path}"
            )

        if os.path.getsize(file_path) == 0:
            return IntegrityCheckResult(
                is_valid=False,
                file_path=file_path,
                file_type="unknown",
                error="Sanitized file is 0 bytes (empty)"
            )

        ext = os.path.splitext(file_path)[1].lower()

        if ext == ".docx":
            return DocumentIntegrityGuard._verify_docx(file_path)
        elif ext == ".pptx":
            return DocumentIntegrityGuard._verify_pptx(file_path)
        elif ext == ".pdf":
            return DocumentIntegrityGuard._verify_pdf(file_path)
        else:
            return IntegrityCheckResult(
                is_valid=False,
                file_path=file_path,
                file_type=ext,
                error=f"Unsupported format for integrity check: {ext}"
            )

    @staticmethod
    def _verify_docx(file_path: str) -> IntegrityCheckResult:
        """Verify DOCX zip archive and WordprocessingML structure."""
        try:
            # 1. Zip container check
            if not zipfile.is_zipfile(file_path):
                return IntegrityCheckResult(
                    is_valid=False,
                    file_path=file_path,
                    file_type=".docx",
                    error="Corrupted container: Not a valid ZIP file"
                )

            with zipfile.ZipFile(file_path, "r") as zf:
                # Test zip integrity (CRC check)
                bad_file = zf.testzip()
                if bad_file:
                    return IntegrityCheckResult(
                        is_valid=False,
                        file_path=file_path,
                        file_type=".docx",
                        error=f"CRC check failed on zip entry: {bad_file}"
                    )

                namelist = zf.namelist()
                if "word/document.xml" not in namelist:
                    return IntegrityCheckResult(
                        is_valid=False,
                        file_path=file_path,
                        file_type=".docx",
                        error="Corrupted DOCX: Missing word/document.xml part"
                    )

            # 2. Parser check via python-docx
            from docx import Document
            doc = Document(file_path)
            # Access paragraphs and tables to verify tree traversal
            _ = len(doc.paragraphs)
            _ = len(doc.tables)

            return IntegrityCheckResult(
                is_valid=True,
                file_path=file_path,
                file_type=".docx"
            )

        except Exception as e:
            return IntegrityCheckResult(
                is_valid=False,
                file_path=file_path,
                file_type=".docx",
                error=f"DOCX parser integrity check failed: {e}"
            )

    @staticmethod
    def _verify_pptx(file_path: str) -> IntegrityCheckResult:
        """Verify PPTX zip archive and presentation structure."""
        try:
            if not zipfile.is_zipfile(file_path):
                return IntegrityCheckResult(
                    is_valid=False,
                    file_path=file_path,
                    file_type=".pptx",
                    error="Corrupted container: Not a valid ZIP file"
                )

            with zipfile.ZipFile(file_path, "r") as zf:
                bad_file = zf.testzip()
                if bad_file:
                    return IntegrityCheckResult(
                        is_valid=False,
                        file_path=file_path,
                        file_type=".pptx",
                        error=f"CRC check failed on zip entry: {bad_file}"
                    )

                namelist = zf.namelist()
                if "ppt/presentation.xml" not in namelist:
                    return IntegrityCheckResult(
                        is_valid=False,
                        file_path=file_path,
                        file_type=".pptx",
                        error="Corrupted PPTX: Missing ppt/presentation.xml part"
                    )

            from pptx import Presentation
            prs = Presentation(file_path)
            _ = len(prs.slides)

            return IntegrityCheckResult(
                is_valid=True,
                file_path=file_path,
                file_type=".pptx"
            )

        except Exception as e:
            return IntegrityCheckResult(
                is_valid=False,
                file_path=file_path,
                file_type=".pptx",
                error=f"PPTX parser integrity check failed: {e}"
            )

    @staticmethod
    def _verify_pdf(file_path: str) -> IntegrityCheckResult:
        """Verify PDF structure and page catalog."""
        try:
            import fitz
            doc = fitz.open(file_path)
            if doc.is_closed or doc.page_count < 1:
                return IntegrityCheckResult(
                    is_valid=False,
                    file_path=file_path,
                    file_type=".pdf",
                    error="PDF has 0 pages or is closed"
                )

            # Probe first page rendering to confirm xref table integrity
            page = doc[0]
            _ = page.rect

            doc.close()
            return IntegrityCheckResult(
                is_valid=True,
                file_path=file_path,
                file_type=".pdf"
            )

        except Exception as e:
            return IntegrityCheckResult(
                is_valid=False,
                file_path=file_path,
                file_type=".pdf",
                error=f"PDF parser integrity check failed: {e}"
            )
