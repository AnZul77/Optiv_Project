# Developer 1: Multimodal Ingestion & Base Architecture Documentation

**Role:** Person 1 — Lead Architect (Ingestion, Dispatcher, Canonical Schema & Security Guardrails)  
**Status:** Implemented, Tested, and Frozen for Team Integration  
**Test Suite:** `tests/unit/test_ingestion.py`, `tests/unit/test_security_limits.py` (15/15 passing)

---

## 1. Architectural Scope & Responsibilities

Developer 1 serves as the foundational architect for the PII Security Firewall gateway. In an OCR-first, multimodal, fail-closed architecture, extraction is the security perimeter:
- If an embedded screenshot, hidden slide, XML text box, or table cell is dropped during ingestion, downstream detection (Person 3) and redaction (Person 2 & 4) will never see it, leading to document leakage.
- If malformed or adversarial inputs (zip bombs, XXE payloads, prompt injections) bypass ingestion, they can crash the service or compromise downstream LLMs.

Developer 1 implements the complete ingestion and pre-processing boundary:
1. **Canonical Document Representation (`src/schema/document.py`)**: Unified object model serving as the contract across all 5 team roles.
2. **Pre-flight Ingestion Validation (`src/ingestion/validators.py`)**: Size checks, extension checks, and magic byte verification.
3. **Multi-Format Routing (`src/ingestion/dispatcher.py`)**: Decorator-based extensible dispatch system with unified results.
4. **Multimodal PDF Extractor (`src/ingestion/pdf.py`)**: Native text blocks, annotation/comment extraction, and 220-dpi scanned page rendering for Person 2's OCR pipeline.
5. **Structural DOCX Extractor (`src/ingestion/docx.py`)**: OpenXML text box (`w:txbxContent`) extraction, table parsing with column-header context inheritance, and embedded screenshot relationship extraction.
6. **Diagram & Hidden Content PPTX Extractor (`src/ingestion/pptx.py`)**: Hierarchical group shape parsing (org charts), hidden slide detection (`<p:sld show="0">`), and speaker notes extraction.
7. **Metadata Extractor & Stripper (`src/ingestion/metadata.py`)**: Extraction and redaction of author, revision, comments, and document properties.
8. **Security Limits & Archive Guard (`src/security/limits.py`)**: Zip bomb detection, expansion ratio guards, XML entity (XXE) blocking, path traversal prevention.
9. **Prompt Injection & Input Safety Isolation (`src/security/input_safety.py`)**: Evasion detection, adversarial Unicode normalization, and XML data-boundary encapsulation.

---

## 2. Component Design & Implementation Details

### 2.1 Canonical Document Schema (`src/schema/document.py`)

The pipeline communicates using standard dataclass objects rather than raw text or format-dependent structures:

- **`BoundingBox`**: Normalized `[x0, y0, x1, y1]` spatial coordinates linked to a page number.
- **`ExtractedBlock`**: Discrete text block (`paragraph`, `heading`, `textbox`, `speaker_note`, `annotation`).
- **`TableCell`**: Individual cell retaining text and its inherited column header (`header_name`) to enable contextual PII resolution.
- **`ExtractedTable`**: Structured table representation with markdown conversion (`to_markdown()`).
- **`ExtractedImage`**: Embedded picture or rendered scanned page with binary payload (`image_bytes`), format, dimensions, screenshot flag, and OCR slots.
- **`ExtractedPage`**: Container for page-level data, including native text, OCR text, blocks, tables, images, and scan detection flags.
- **`EntityAnnotation`**: Standard PII entity contract conforming to PRD Section 3.2. Provides `EntityAnnotation.create()` which computes a salted SHA-256 hash (`value_hash`) to ensure zero raw PII is ever recorded in memory or audit trails.
- **`CanonicalDocument`**: Aggregated document container with convenience accessors: `get_full_text()`, `get_all_images()`, `get_all_tables()`, and `add_page()`.
- **`PipelineMetadata`**: Telemetry tracker capturing file size, extraction duration, OCR engine name, extractor version, and security warnings.

---

### 2.2 Security Guardrails & Pre-flight Validation

#### Archive & Zip Safety (`src/security/limits.py`)
Both DOCX and PPTX are OpenXML packages (ZIP archives). To mitigate Denial-of-Service and decompression attacks:
- **Zip Bomb Guard**: Measures total uncompressed size against a hard cap (350 MB) and computes decompression ratio. If the expansion ratio exceeds `100:1`, extraction is aborted with `SecurityLimitExceededError`.
- **Entry Count Limits**: Maximum of 10,000 files per archive.
- **Path Traversal Guard**: Rejects archives containing entries with `../` or root-absolute paths (`/`, `\`).
- **XXE Prevention (`inspect_xml_content_safety`)**: Blocks XML parts containing `<!DOCTYPE` with `SYSTEM` or `<!ENTITY` definitions.

#### Pre-flight Ingestion Validator (`src/ingestion/validators.py`)
Documents pass through `validate_document()` before parsing:
1. File existence and non-zero byte size check.
2. Security limits check (`check_file_size`).
3. Extension verification against allowed list (`.pdf`, `.docx`, `.pptx`).
4. **Magic Byte Signature Inspection (`inspect_magic_bytes`)**:
   - PDF files must start with `%PDF-` (`b"%PDF-"`).
   - DOCX and PPTX files must start with ZIP magic bytes (`b"PK\x03\x04"`).
   - Verifies presence of internal OpenXML directories (`word/` or `ppt/`) to prevent extension-spoofing attacks.

---

### 2.3 Format-Specific Multimodal Extractors

#### 1. PDF Extractor (`src/ingestion/pdf.py`)
- Employs PyMuPDF (`fitz`) with a graceful fallback to `pypdf`.
- **Native Text Handling**: Extracts text grouped by spatial blocks (`(x0, y0, x1, y1, text)`).
- **Scanned Page Rendering**: Scanned pages or pages flagged for OCR are rendered to high-resolution PNG bytes at **220 DPI** (`render_dpi=220`), packaged as `ExtractedImage`, and queued for Person 2's OCR engine.
- **Annotations & Forms**: Extracts annotations, notes, and form fields into `ExtractedBlock(block_type="annotation")` to catch covert PII in margin comments.

#### 2. DOCX Extractor (`src/ingestion/docx.py`)
- **Paragraphs & Layout**: Extracts body paragraphs and detects OpenXML page breaks (`w:br[@w:type="page"]` and `w:lastRenderedPageBreak`).
- **XML Text Boxes**: Directly parses WordprocessingML `w:txbxContent` elements to extract text boxes often missed by naive paragraph iterators.
- **Table Context Resolution**: Iterates through tables, treating row 0 as column headers. For every cell, the column header is attached to `TableCell.header_name`. This solves the PRD challenge where values like `"EMP-9481"` or `"987-65-4321"` require their column header (e.g., `"Employee ID"`, `"SSN"`) to trigger context rules.
- **Embedded Screenshots**: Inspects relationship parts (`doc.part.rels`), extracts image blobs, tags images over 20 KB as candidate screenshots (`is_screenshot=True`), and populates `ExtractedPage.images`.

#### 3. PPTX Extractor (`src/ingestion/pptx.py`)
- **Hierarchical Group Shapes**: Uses recursive shape processing (`_process_shapes`) to unpack nested `GroupShape` trees commonly used in organizational charts and architecture diagrams.
- **Hidden Slide Detection**: Inspects OpenXML slide attributes (`<p:sld show="0">`). Flagged slides are marked with `metadata["is_hidden_slide"] = True`, ensuring unredacted PII hidden in draft slides is not leaked.
- **Speaker Notes Extraction**: Extracts slide notes from `slide.notes_slide.notes_text_frame` into `ExtractedBlock(block_type="speaker_note", is_hidden=True)`, neutralizing notes as a covert PII channel.

---

### 2.4 Metadata & Input Safety Isolation

#### Metadata Extraction & Stripping (`src/ingestion/metadata.py`)
- `MetadataExtractor`: Aggregates core properties across formats (author, last modified by, revision history, creation date, comments).
- `MetadataSanitizer`: Provides zero-PII sanitization routines (`sanitize_pdf_properties`, `sanitize_docx_properties`, `sanitize_pptx_properties`) replacing author names and modifying entities with `[REDACTED]`.

#### Input Safety & Prompt Injection Isolation (`src/security/input_safety.py`)
- Scans extracted text against known prompt injection and jailbreak signatures.
- **Unicode Evasion Defense**: Detects and strips invisible characters (`ZERO WIDTH SPACE`, `LEFT-TO-RIGHT OVERRIDE`, soft hyphens) used by adversarial actors to evade detection (e.g. `"R\u200ba\u200bh\u200bu\u200bl"` $\rightarrow$ `"Rahul"`).
- **Data Isolation Envelope (`isolate_for_llm_consumption`)**: Wraps extracted document text inside inert XML delimiters (`<document_payload role="data_only">`) with warning comments instructing downstream LLMs to treat content as untrusted data.

---

## 3. Verification & Test Execution

Run the complete test suite with:
```powershell
python -m pytest tests/unit/ -v
```

### Test Coverage Summary:
- `test_check_file_size`: Normal files, missing files, empty files, size threshold violations.
- `test_inspect_archive_safety_path_traversal`: Malicious archives containing `../` traversal paths.
- `test_inspect_archive_safety_zip_bomb`: High-compression ratio archive explosion triggers.
- `test_inspect_xml_content_safety`: Clean XML vs. malicious XML with XXE `<!DOCTYPE` injection.
- `test_input_safety_guard_prompt_injection`: Benign text vs. jailbreak prompts.
- `test_input_safety_guard_unicode_anomalies`: Zero-width space evasion detection & cleaning.
- `test_input_safety_guard_isolation`: Packaging payload in data-only XML tags.
- `test_validate_document_success`: End-to-end format validation on PDF, DOCX, and PPTX.
- `test_validate_document_mismatch`: Detection of spoofed file extensions via magic bytes.
- `test_pdf_extraction`: Native text extraction, block coordinates, metadata.
- `test_docx_extraction`: Paragraphs, tables, and column-header inheritance.
- `test_pptx_extraction`: Slides, diagram shapes, and speaker notes covert channel.
- `test_dispatcher_routing`: Registry lookup, automated dispatching, execution summary.
- `test_metadata_extraction_and_sanitization`: Metadata extraction and property stripping.
- `test_canonical_document_entity_creation`: Salted SHA-256 entity creation with zero raw PII retention.
