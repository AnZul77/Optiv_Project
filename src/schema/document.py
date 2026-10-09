"""
Canonical Document Object Models
Person 1: Lead Architect
Defines standard document, structural, and entity representations used across the pipeline.
Frozen contract for Person 1 (Ingestion), Person 2 (OCR), Person 3 (PII Detection),
Person 4 (Policy & Verification), and Person 5 (Evaluation & UI).
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone
import uuid
import hashlib


@dataclass
class BoundingBox:
    """Normalized spatial coordinates [x0, y0, x1, y1] on a document page."""
    x0: float
    y0: float
    x1: float
    y1: float
    page: int = 1

    def to_list(self) -> List[float]:
        return [self.x0, self.y0, self.x1, self.y1]

    @classmethod
    def from_list(cls, coords: List[float], page: int = 1) -> BoundingBox:
        if len(coords) != 4:
            raise ValueError(f"Expected 4 coordinate values, got {len(coords)}")
        return cls(x0=coords[0], y0=coords[1], x1=coords[2], y1=coords[3], page=page)


@dataclass
class ExtractedImage:
    """An embedded image or rendered page extracted from a document."""
    image_id: str
    page: int
    image_bytes: bytes = field(repr=False)
    image_format: str  # e.g., "png", "jpeg", "bmp"
    width: int = 0
    height: int = 0
    bbox: Optional[List[float]] = None  # [x0, y0, x1, y1] if localized on page
    relationship_id: Optional[str] = None
    is_screenshot: bool = False
    ocr_text: str = ""
    ocr_confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TableCell:
    """A single cell inside an extracted table with inherited header context."""
    row_idx: int
    col_idx: int
    text: str
    header_name: str = ""  # Inherited column header for PII context resolution
    bbox: Optional[List[float]] = None


@dataclass
class ExtractedTable:
    """A structured table extracted from DOCX, PDF, or PPTX."""
    table_index: int
    page: int
    headers: List[str] = field(default_factory=list)
    rows: List[List[TableCell]] = field(default_factory=list)
    raw_markdown: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_markdown(self) -> str:
        """Render table to markdown string with header row."""
        if not self.headers and not self.rows:
            return ""
        lines = []
        if self.headers:
            lines.append("| " + " | ".join(self.headers) + " |")
            lines.append("| " + " | ".join(["---"] * len(self.headers)) + " |")
        for row in self.rows:
            lines.append("| " + " | ".join(cell.text for cell in row) + " |")
        return "\n".join(lines)


@dataclass
class ExtractedBlock:
    """A discrete block of text (paragraph, heading, text box, speaker note, etc.)."""
    block_id: str
    page: int
    block_type: str  # "paragraph", "heading", "textbox", "speaker_note", "table_cell"
    text: str
    bbox: Optional[List[float]] = None
    style_name: Optional[str] = None
    is_hidden: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractedPage:
    """A canonical representation of a single document page / slide."""
    page_num: int
    native_text: str = ""
    ocr_text: str = ""
    ocr_confidence: float = 1.0
    has_native_text: bool = True
    is_scanned: bool = False
    blocks: List[ExtractedBlock] = field(default_factory=list)
    tables: List[ExtractedTable] = field(default_factory=list)
    images: List[ExtractedImage] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def combined_text(self) -> str:
        """Returns the primary accessible text for this page (native or OCR)."""
        if self.native_text and self.native_text.strip():
            return self.native_text
        return self.ocr_text


@dataclass
class EntityAnnotation:
    """
    A detected PII entity with spatial and semantic metadata.
    Conforms directly to PRD Section 3.2 schema.
    """
    entity_id: str
    type: str  # e.g., "EMAIL", "SSN", "PERSON", "ADDRESS", "PAN", "AADHAAR"
    source: str  # "ocr", "native", "regex", "ner", "context"
    value_hash: str  # SHA-256 hash of the raw value (never store raw PII in logs)
    page: int
    bbox: List[float] = field(default_factory=lambda: [0.0, 0.0, 0.0, 0.0])  # [x0, y0, x1, y1]
    text_start: int = 0  # Character offset within page/block text
    text_end: int = 0
    confidence: float = 1.0  # 0.0 to 1.0
    risk: str = "HIGH"  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    action: str = "REDACT"  # "REDACT", "BLOCK", "PASS"
    context: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        entity_type: str,
        raw_value: str,
        source: str,
        page: int,
        bbox: Optional[List[float]] = None,
        text_start: int = 0,
        text_end: int = 0,
        confidence: float = 1.0,
        risk: str = "HIGH",
        action: str = "REDACT",
        context: Optional[Dict[str, Any]] = None,
        salt: str = ""
    ) -> EntityAnnotation:
        """Factory method computing salted SHA-256 hash without keeping raw text."""
        hashed = hashlib.sha256((salt + raw_value).encode("utf-8")).hexdigest()
        return cls(
            entity_id=f"urn:uuid:{uuid.uuid4()}",
            type=entity_type,
            source=source,
            value_hash=hashed,
            page=page,
            bbox=bbox or [0.0, 0.0, 0.0, 0.0],
            text_start=text_start,
            text_end=text_end,
            confidence=confidence,
            risk=risk,
            action=action,
            context=context or {}
        )


@dataclass
class CanonicalDocument:
    """
    The canonical document representation that flows through the firewall pipeline.
    Created after extraction and consumed by OCR, detection, redaction, and verification.
    """
    doc_id: str
    source_path: str
    filename: str
    file_type: str  # ".pdf", ".docx", ".pptx"
    pages: int
    pages_dict: Dict[int, ExtractedPage] = field(default_factory=dict)
    native_text: Dict[int, str] = field(default_factory=dict)  # page_num -> native text
    ocr_text: Dict[int, str] = field(default_factory=dict)  # page_num -> OCR text
    ocr_confidence: Dict[int, float] = field(default_factory=dict)  # page_num -> confidence
    entities: List[EntityAnnotation] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    revision: int = 0

    def __post_init__(self):
        if not self.doc_id:
            self.doc_id = str(uuid.uuid4())
        # Synchronize pages_dict with native_text/ocr_text dictionaries if needed
        for p in range(1, self.pages + 1):
            if p not in self.pages_dict:
                self.pages_dict[p] = ExtractedPage(
                    page_num=p,
                    native_text=self.native_text.get(p, ""),
                    ocr_text=self.ocr_text.get(p, ""),
                    ocr_confidence=self.ocr_confidence.get(p, 1.0)
                )

    def get_full_text(self) -> str:
        """Aggregate full text from all pages in logical reading order."""
        chunks = []
        for p in sorted(self.pages_dict.keys()):
            page = self.pages_dict[p]
            text = page.combined_text
            if text.strip():
                chunks.append(f"--- Page {p} ---\n{text}")
        return "\n\n".join(chunks)

    def get_all_images(self) -> List[ExtractedImage]:
        """Collect all embedded images and rendered visual pages across document."""
        images = []
        for p in sorted(self.pages_dict.keys()):
            images.extend(self.pages_dict[p].images)
        return images

    def get_all_tables(self) -> List[ExtractedTable]:
        """Collect all structured tables across document."""
        tables = []
        for p in sorted(self.pages_dict.keys()):
            tables.extend(self.pages_dict[p].tables)
        return tables

    def add_page(self, page: ExtractedPage) -> None:
        """Add or update an extracted page and synchronize dictionaries."""
        self.pages_dict[page.page_num] = page
        self.native_text[page.page_num] = page.native_text
        self.ocr_text[page.page_num] = page.ocr_text
        self.ocr_confidence[page.page_num] = page.ocr_confidence
        self.pages = max(self.pages, page.page_num)


@dataclass
class PipelineMetadata:
    """Metadata accumulated across the pipeline stages."""
    extraction_time: Optional[float] = None
    detection_time: Optional[float] = None
    redaction_time: Optional[float] = None
    verification_time: Optional[float] = None
    ocr_engine: Optional[str] = None
    extractor_version: Optional[str] = None
    detector_version: Optional[str] = None
    file_size_bytes: int = 0
    security_checks_passed: bool = True
    warnings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class ExtractionResult:
    """Result of a document extraction operation."""
    success: bool
    document: Optional[CanonicalDocument] = None
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    pipeline_metadata: Optional[PipelineMetadata] = None