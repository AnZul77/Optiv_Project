"""
Schema Package
Canonical document representation and entity schemas.
"""

from .document import (
    CanonicalDocument,
    ExtractedPage,
    ExtractedBlock,
    ExtractedImage,
    ExtractedTable,
    TableCell,
    BoundingBox,
    EntityAnnotation,
    ExtractionResult,
    PipelineMetadata,
)

__all__ = [
    "CanonicalDocument",
    "ExtractedPage",
    "ExtractedBlock",
    "ExtractedImage",
    "ExtractedTable",
    "TableCell",
    "BoundingBox",
    "EntityAnnotation",
    "ExtractionResult",
    "PipelineMetadata",
]
