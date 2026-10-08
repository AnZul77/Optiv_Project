# Team Integration Guide & Interface Contract

**Author:** Developer 1 (Lead Architect — Ingestion & Ingestion Security)  
**Recipients:** Developer 2 (OCR/Vision), Developer 3 (PII Detection), Developer 4 (Policy & Verification), Developer 5 (Evaluation & UI), and OpenRouter Coordinator.  
**Version:** 1.0.0 (Extractor Checkpoint Frozen)  

---

## 1. Executive Summary

This document establishes the frozen interface contract for the **PII Security Firewall**. All modules ingest or produce the canonical data structures defined in `src/schema/document.py`. 

By strictly adhering to these schemas and contracts, all 5 team members can develop their modules in parallel without blocked dependencies or interface drift.

```
Incoming File (PDF, DOCX, PPTX)
           │
           ▼
[Person 1: Ingestion & Safety]  ──► CanonicalDocument (Blocks, Tables, Images, Metadata)
           │
           ├──────────────────────────────┐
           ▼                              ▼
[Person 2: OCR Engine]          [Person 3: PII Detection]
  (Consumes ExtractedImage)       (Consumes Text, Tables & Header Context)
  (Generates OCR text & bboxes)   (Emits EntityAnnotation list)
           │                              │
           └──────────────┬───────────────┘
                          ▼
            [Person 4: Policy & Verifier]
              (Enforces Risk, Policy & Independent Re-OCR Verifier)
              (Zero-PII Audit Logger & AI Ready Gate)
                          │
                          ▼
            [Person 5: Evaluation & Streamlit UI]
              (Benchmark Metrics, Adversarial Tests & Gateway Dashboard)
```

---

## 2. Shared Data Contract (`src/schema/document.py`)

All team members must import shared models directly from `src.schema.document`:

```python
from src.schema.document import (
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
```

### 2.1 Canonical Document Schema Breakdown

| Class | Key Attributes | Produced By | Consumed By |
|---|---|---|---|
| **`CanonicalDocument`** | `doc_id`, `filename`, `pages`, `pages_dict`, `metadata`, `entities` | Person 1 | All (P2, P3, P4, P5) |
| **`ExtractedPage`** | `page_num`, `native_text`, `ocr_text`, `blocks`, `tables`, `images`, `is_scanned` | Person 1 | P2, P3, P4 |
| **`ExtractedBlock`** | `block_id`, `page`, `block_type`, `text`, `bbox`, `is_hidden` | Person 1, P2 | P3, P4, P5 |
| **`ExtractedTable`** | `table_index`, `page`, `headers`, `rows`, `raw_markdown` | Person 1 | P3 (Context Engine) |
| **`TableCell`** | `row_idx`, `col_idx`, `text`, `header_name`, `bbox` | Person 1 | P3 (Context Engine) |
| **`ExtractedImage`** | `image_id`, `page`, `image_bytes`, `image_format`, `is_screenshot` | Person 1 | P2 (OCR & Redactor) |
| **`EntityAnnotation`** | `entity_id`, `type`, `source`, `value_hash`, `bbox`, `confidence`, `risk` | P3 (Detector), P4 (Verifier) | P4 (Policy), P5 (UI) |

---

## 3. Integration Directives per Role

### 3.1 Developer 2 (OCR & Vision Lead)

**Your Inputs from Person 1:**
- Rendered scanned PDF pages (220-DPI PNG bytes) are stored in `page.images` with `metadata={"rendered_page": True}`.
- Embedded screenshots in DOCX and diagrams in PPTX are stored in `page.images` with `is_screenshot=True`.

**How to Access Images:**
```python
from src.ingestion.dispatcher import dispatch_extraction

# Extract document
result = dispatch_extraction("data/raw/sample.docx")
doc = result.document

# Iterate through visual assets needing OCR
for img in doc.get_all_images():
    image_bytes = img.image_bytes
    img_id = img.image_id
    
    # Run OCR inference (EasyOCR / PaddleOCR)
    ocr_result = ocr_engine.extract(image_bytes)
    img.ocr_text = ocr_result["text"]
    img.ocr_confidence = ocr_result["confidence"]
```

**Pixel Burning Contract for Sanitization:**
- Use OpenCV / Pillow to permanently draw opaque black boxes over sensitive bounding boxes (`[x0, y0, x1, y1]`).
- Do **not** use overlay layers; permanently overwrite underlying image bytes.

---

### 3.2 Developer 3 (PII Detection Lead)

**Your Inputs from Person 1:**
- Extracted text per page: `page.combined_text` (or `page.native_text` + `page.ocr_text`).
- Structural blocks: `page.blocks` (includes `paragraph`, `heading`, `textbox`, `speaker_note`, `annotation`).
- Tables with Column Header Inheritance: `table.rows` where each `TableCell` has `header_name`.

**How to Utilize Table Context for PII Detection:**
```python
# Resolve contextual cues from inherited headers (e.g. Employee ID, SSN)
for table in doc.get_all_tables():
    for row in table.rows:
        for cell in row:
            # cell.header_name contains inherited column name!
            # cell.text contains the cell value
            if "tax" in cell.header_name.lower() or "pan" in cell.header_name.lower():
                # Apply tax/PAN regex or boost confidence!
                pass
```

**Entity Creation Standard (Zero-PII Compliance):**
Always instantiate detected entities using `EntityAnnotation.create()` to guarantee salted SHA-256 hashing without storing plaintext PII in logs:
```python
entity = EntityAnnotation.create(
    entity_type="SSN",
    raw_value=detected_str,
    source="regex",
    page=page_num,
    bbox=[x0, y0, x1, y1],
    text_start=start_idx,
    text_end=end_idx,
    confidence=0.98,
    risk="CRITICAL",
    action="REDACT",
    salt="optiv_enterprise_salt"
)
doc.entities.append(entity)
```

---

### 3.3 Developer 4 (Security Policy, Verifier & Audit Lead)

**Your Inputs from Person 1:**
- Document metadata: `doc.metadata` (contains author, creation date, revision, hidden slides count, notes count).
- Input safety scanner: `src.security.input_safety.InputSafetyGuard`.
- Metadata Sanitizer: `src.ingestion.metadata.MetadataSanitizer`.

**How to Invoke Pre-flight Security and Metadata Stripping:**
```python
from src.security.limits import check_file_size, inspect_archive_safety
from src.security.input_safety import InputSafetyGuard
from src.ingestion.metadata import MetadataSanitizer

# 1. Sanitize file properties before downstream delivery
MetadataSanitizer.sanitize_docx_properties(input_path, sanitized_path)

# 2. Wrap output text in inert LLM data payload
guard = InputSafetyGuard()
inert_payload, report = guard.isolate_for_llm_consumption(sanitized_text, doc_id=doc.doc_id)
```

**Fail-Closed Gate Rule:**
- If `page.ocr_confidence < 0.60` on a page containing suspected PII patterns $\rightarrow$ **BLOCK**.
- If independent verifier finds residual critical PII after redaction $\rightarrow$ **BLOCK**.

---

### 3.4 Developer 5 (Evaluation, Benchmark & UI Lead)

**Your Inputs from Person 1:**
- Uniform execution entry point: `route_document(file_path)` and `batch_route(file_paths)`.
- Coordinate representation: Normalized `BoundingBox` `[x0, y0, x1, y1]` for matching against ground truth.

**How to Run Ingestion in Streamlit or Benchmark Harness:**
```python
from src.ingestion.dispatcher import route_document

# In your Streamlit upload handler:
result = route_document(uploaded_temp_file_path)

if result["status"] == "EXTRACTED":
    doc = result["document"]
    st.success(f"Extracted {doc.pages} pages from {doc.filename}")
    st.metric("Total Visual Assets", len(doc.get_all_images()))
    st.metric("Total Tables", len(doc.get_all_tables()))
else:
    st.error(f"Ingestion rejected: {result['error']}")
```

---

## 4. Quality & Testing Standards

Before merging code or handing off between team roles, verify that all ingestion tests pass:
```powershell
python -m pytest tests/unit/ -v
```
All components must maintain zero unhandled exceptions on corrupt, adversarial, or unexpected inputs, returning structured error messages rather than crashing the gateway process.
