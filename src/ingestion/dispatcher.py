"""
Multi-Format Document Dispatcher
Person 1: Lead Architect
Unified entry point that routes documents to format-specific extractors (PDF, DOCX, PPTX)
with pre-flight security validation and structured result reporting.
Roadmap: Day 6 - Unified Dispatcher
"""

from __future__ import annotations
import os
import time
from typing import Dict, Type, Optional, Any, List

from .validators import validate_document, ValidationResult
from .pdf import PDFExtractor
from .docx import DOCXExtractor
from .pptx import PPTXExtractor
from ..schema.document import CanonicalDocument, ExtractionResult, PipelineMetadata
from ..security.limits import SecurityLimitsConfig


# Registry of supported file handlers
HANDLER_REGISTRY: Dict[str, Type] = {}


def register_handler(extension: str):
    """Decorator to register a document handler for a specific file extension."""
    def decorator(cls):
        HANDLER_REGISTRY[extension.lower()] = cls
        return cls
    return decorator


def get_handler(extension: str) -> Optional[Type]:
    """Retrieve registered handler class for the given extension."""
    return HANDLER_REGISTRY.get(extension.lower())


class BaseDocumentHandler:
    """Base class for format-specific document extraction handlers."""
    supported_extensions: List[str] = []

    def __init__(self, ocr_engine=None):
        self.ocr_engine = ocr_engine

    def extract(self, file_path: str, metadata: Optional[Dict[str, Any]] = None) -> ExtractionResult:
        raise NotImplementedError


@register_handler(".pdf")
class PDFHandler(BaseDocumentHandler):
    supported_extensions = [".pdf"]

    def extract(self, file_path: str, metadata: Optional[Dict[str, Any]] = None) -> ExtractionResult:
        try:
            extractor = PDFExtractor(ocr_engine=self.ocr_engine)
            doc, meta = extractor.extract(file_path, metadata or {})
            return ExtractionResult(success=True, document=doc, pipeline_metadata=meta)
        except Exception as e:
            return ExtractionResult(success=False, error=f"PDF extraction failed: {e}")


@register_handler(".docx")
class DOCXHandler(BaseDocumentHandler):
    supported_extensions = [".docx"]

    def extract(self, file_path: str, metadata: Optional[Dict[str, Any]] = None) -> ExtractionResult:
        try:
            extractor = DOCXExtractor(ocr_engine=self.ocr_engine)
            doc, meta = extractor.extract(file_path, metadata or {})
            return ExtractionResult(success=True, document=doc, pipeline_metadata=meta)
        except Exception as e:
            return ExtractionResult(success=False, error=f"DOCX extraction failed: {e}")


@register_handler(".pptx")
class PPTXHandler(BaseDocumentHandler):
    supported_extensions = [".pptx"]

    def extract(self, file_path: str, metadata: Optional[Dict[str, Any]] = None) -> ExtractionResult:
        try:
            extractor = PPTXExtractor(ocr_engine=self.ocr_engine)
            doc, meta = extractor.extract(file_path, metadata or {})
            return ExtractionResult(success=True, document=doc, pipeline_metadata=meta)
        except Exception as e:
            return ExtractionResult(success=False, error=f"PPTX extraction failed: {e}")


def dispatch_extraction(
    file_path: str,
    ocr_engine=None,
    metadata: Optional[Dict[str, Any]] = None,
    limits_config: Optional[SecurityLimitsConfig] = None,
    skip_validation: bool = False
) -> ExtractionResult:
    """
    Validate and dispatch a document to the appropriate extraction handler.
    
    Args:
        file_path: Path to the target document.
        ocr_engine: Optional OCR engine adapter.
        metadata: Custom metadata dictionary.
        limits_config: Security limits configuration.
        skip_validation: If True, bypasses pre-flight security checks (not recommended).
        
    Returns:
        ExtractionResult containing the CanonicalDocument or error.
    """
    # Step 1: Pre-flight security & format validation
    if not skip_validation:
        val_result = validate_document(file_path, limits_config=limits_config)
        if not val_result.is_valid:
            return ExtractionResult(
                success=False,
                error=f"Security/Format validation failed: {val_result.error}",
                warnings=val_result.warnings
            )

    # Step 2: Route by extension
    ext = os.path.splitext(file_path)[1].lower()
    handler_cls = get_handler(ext)
    if not handler_cls:
        return ExtractionResult(
            success=False,
            error=f"No extractor registered for '{ext}'. Supported: {', '.join(HANDLER_REGISTRY.keys())}"
        )

    # Step 3: Execute extraction
    handler = handler_cls(ocr_engine=ocr_engine)
    return handler.extract(file_path, metadata or {})


def route_document(
    file_path: str,
    ocr_engine=None,
    policy_config: Optional[Dict[str, Any]] = None,
    limits_config: Optional[SecurityLimitsConfig] = None
) -> Dict[str, Any]:
    """
    Main pipeline entry point: routes a document through validation and extraction,
    returning structured execution summary for downstream engines.
    """
    res = dispatch_extraction(file_path, ocr_engine=ocr_engine, limits_config=limits_config)
    
    if not res.success:
        return {
            "status": "FAILED",
            "file_path": file_path,
            "error": res.error,
            "warnings": res.warnings,
            "document": None
        }

    doc = res.document
    meta = res.pipeline_metadata

    summary = {
        "status": "EXTRACTED",
        "file_path": file_path,
        "document_id": doc.doc_id,
        "filename": doc.filename,
        "file_type": doc.file_type,
        "total_pages": doc.pages,
        "has_native_text": any(p.has_native_text for p in doc.pages_dict.values()),
        "total_images": len(doc.get_all_images()),
        "total_tables": len(doc.get_all_tables()),
        "extraction_time_seconds": meta.extraction_time if meta else None,
        "ocr_engine": meta.ocr_engine if meta else None,
        "document": doc,
    }

    if policy_config:
        summary["policy_config"] = policy_config

    return summary


def batch_route(
    file_paths: List[str],
    ocr_engine=None,
    policy_config: Optional[Dict[str, Any]] = None,
    limits_config: Optional[SecurityLimitsConfig] = None
) -> List[Dict[str, Any]]:
    """Route multiple documents sequentially with isolated error handling."""
    return [
        route_document(fp, ocr_engine=ocr_engine, policy_config=policy_config, limits_config=limits_config)
        for fp in file_paths
    ]


def list_supported_formats() -> List[str]:
    """List of registered file extensions."""
    return list(HANDLER_REGISTRY.keys())