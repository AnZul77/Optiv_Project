"""
Ingestion Package
Person 1: Lead Architect
Multimodal Document Extraction, Pre-flight Security Validation, and Dispatching.
"""

from .validators import validate_document, ValidationResult, inspect_magic_bytes
from .dispatcher import (
    dispatch_extraction,
    route_document,
    batch_route,
    list_supported_formats,
    register_handler,
    get_handler,
)
from .pdf import PDFExtractor
from .docx import DOCXExtractor
from .pptx import PPTXExtractor
from .metadata import MetadataExtractor, MetadataSanitizer

__all__ = [
    "validate_document",
    "ValidationResult",
    "inspect_magic_bytes",
    "dispatch_extraction",
    "route_document",
    "batch_route",
    "list_supported_formats",
    "register_handler",
    "get_handler",
    "PDFExtractor",
    "DOCXExtractor",
    "PPTXExtractor",
    "MetadataExtractor",
    "MetadataSanitizer",
]
