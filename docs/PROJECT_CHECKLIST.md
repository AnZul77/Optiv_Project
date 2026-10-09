# PII Security Firewall: Master Project Checklist

**Current Status:** Week 1 Foundational Phase Complete (Developer 1 Extractor Checkpoint Frozen)  
**Test Suite Status:** 15/15 Unit Tests Passing (`python -m pytest tests/unit/ -v`)  
**Architecture Contract:** Standardized on `src/schema/document.py`  

---

## 1. Developer 1: Lead Architect (Ingestion, Dispatcher & Base Security)

### ✅ Completed Tasks (Done)
- [x] **Canonical Schema Definition (`src/schema/document.py`)**:
  - [x] Implemented `CanonicalDocument` model with pages, blocks, tables, images, and metadata.
  - [x] Implemented `ExtractedPage`, `ExtractedBlock`, `ExtractedTable`, `TableCell`, and `ExtractedImage`.
  - [x] Implemented `BoundingBox` normalized coordinate system.
  - [x] Implemented `EntityAnnotation` with salted SHA-256 value hashing (zero plaintext PII).
  - [x] Implemented `ExtractionResult` and `PipelineMetadata` execution telemetry.
- [x] **Pre-flight Ingestion Validation (`src/ingestion/validators.py`)**:
  - [x] Implemented `validate_document()` pre-flight verification.
  - [x] Implemented `inspect_magic_bytes()` (PDF `%PDF-`, DOCX/PPTX `PK\x03\x04`).
  - [x] Implemented extension and empty file validation.
  - [x] Implemented deep container verification for Office OpenXML formats (`word/`, `ppt/`).
- [x] **Multi-Format Dispatcher (`src/ingestion/dispatcher.py`)**:
  - [x] Implemented extensible `@register_handler()` decorator and handler registry.
  - [x] Implemented `dispatch_extraction()` with pre-flight security gating.
  - [x] Implemented `route_document()` and `batch_route()` with structured status dictionaries.
- [x] **Multimodal PDF Extractor (`src/ingestion/pdf.py`)**:
  - [x] Implemented PyMuPDF (`fitz`) native text extraction with block coordinates.
  - [x] Implemented `pypdf` fallback engine.
  - [x] Implemented 220-DPI high-resolution scanned page rendering to PNG bytes for Person 2 OCR.
  - [x] Implemented PDF annotations, notes, and comments extraction.
- [x] **DOCX Extractor (`src/ingestion/docx.py`)**:
  - [x] Implemented native paragraph extraction with page break tracking.
  - [x] Implemented OpenXML text box extraction (`w:txbxContent`).
  - [x] Implemented table extraction with cell-level column header context inheritance (`header_name`).
  - [x] Implemented embedded image/screenshot extraction from relationships with screenshot tagging.
- [x] **PPTX Extractor (`src/ingestion/pptx.py`)**:
  - [x] Implemented slide shape extraction with recursive hierarchical group shape parsing (org charts).
  - [x] Implemented hidden slide detection via OpenXML `<p:sld show="0">`.
  - [x] Implemented speaker notes extraction to uncover covert PII channels.
  - [x] Implemented slide table and embedded picture extraction.
- [x] **Metadata & Sanitization (`src/ingestion/metadata.py`)**:
  - [x] Implemented cross-format `MetadataExtractor` for author, revisions, and properties.
  - [x] Implemented `MetadataSanitizer` routines for zero-PII metadata stripping.
- [x] **Security Limits & Guardrails (`src/security/limits.py`)**:
  - [x] Implemented `check_file_size()` with configurable maximum size thresholds.
  - [x] Implemented `inspect_archive_safety()` (zip bomb expansion ratio, entry limits, path traversal `../`).
  - [x] Implemented `inspect_xml_content_safety()` (XXE / external entity expansion guard).
- [x] **Input Safety & Prompt Isolation (`src/security/input_safety.py`)**:
  - [x] Implemented `scan_for_prompt_injection()` detecting jailbreak patterns.
  - [x] Implemented `detect_unicode_anomalies()` and `strip_adversarial_unicode()` for zero-width spaces/BiDi.
  - [x] Implemented `isolate_for_llm_consumption()` wrapping extracted text in inert XML boundaries.
- [x] **Sanitization & Document Reconstruction (`src/sanitization/docx_reconstructor.py`)**:
  - [x] Native DOCX text replacement across paragraphs, table cells, and text boxes preserving fonts/styles.
  - [x] Embedded screenshot image swapper for OpenXML relationship parts.
- [x] **Post-Redaction Document Integrity Guard (`src/security/integrity.py`)**:
  - [x] Automated open-and-read parse check across DOCX, PPTX, and PDF to fail-closed on corrupt output files.
- [x] **Master Documentation & Repository Setup**:
  - [x] Authored repository `README.md` with complete setup and test guides.
  - [x] Authored `docs/architecture.md` with master system architecture, data flow, and fail-closed state table.
  - [x] Authored `docs/developer_1_ingestion_architecture.md`.
  - [x] Authored `docs/developer_2_ocr_vision_architecture.md`.
  - [x] Authored `docs/developer_3_pii_detection_architecture.md`.
  - [x] Authored `docs/developer_4_policy_verifier_architecture.md`.
  - [x] Authored `docs/developer_5_evaluation_ui_architecture.md`.
  - [x] Authored `docs/TEAM_INTEGRATION_GUIDE.md`.
  - [x] Authored `docs/PROJECT_CHECKLIST.md`.
- [x] **Unit Testing**:
  - [x] Built `tests/unit/test_ingestion.py`, `tests/unit/test_security_limits.py`, and `tests/unit/test_reconstruction.py` (**19/19 passing**).

### ⏳ Developer 1 Remaining Deliverables (Roadmap Integration)
- [ ] **Day 8 (Week 2):** Implement document structure retention trackers (heading hierarchy and layout metadata).
- [ ] **Day 14 (Week 2):** Week 2 integration review & end-to-end extraction-to-redaction smoke test with Dev 2–4.
- [ ] **Day 15 (Week 3):** Stress test file ingestion with high concurrency and edge archives.
- [ ] **Day 17 (Week 3):** Adversarial input validation against corrupt zips, XML bombs, and path traversals.
- [ ] **Day 19 (Week 3):** Connect document upload and status callbacks to Streamlit UI (`app.py`).

---

## 2. Developer 2: OCR Engine & Image Redaction Lead

### ⏳ Tasks Left to be Done
- [ ] **Day 1–2:** Verify OCR engines (`PaddleOCR` vs `EasyOCR`) on local CPU/GPU; test on 35-page Risk Policy PDF.
- [ ] **Day 2:** Implement `src/ocr/engine.py` (OCR adapter) and `src/ocr/preprocess.py` (contrast/binarization, 220-dpi).
- [ ] **Day 3:** Extract and test OCR on all 38 OneTrust screenshots from TPRM DOCX.
- [ ] **Day 4:** Implement `src/ocr/regions.py` for bounding-box extraction and coordinate normalization.
- [ ] **Day 5:** Freeze image extraction and OCR coordinates so ground-truth annotations do not drift.
- [ ] **Day 6:** Implement OCR confidence scoring in `src/ocr/confidence.py` (flagging low-confidence characters).
- [ ] **Day 7:** Benchmark OCR latency across sample pages and optimize memory use.
- [ ] **Day 8:** Build bounding-box coordinate transformer for image replacement.
- [ ] **Day 9:** Build image mask bounding-box calculator with safety padding.
- [ ] **Day 10:** Implement `src/sanitization/image_redactor.py` (permanent pixel burning with OpenCV/Pillow).
- [ ] **Day 10:** Implement `src/sanitization/pdf_redactor.py` (opaque burned boxes on scanned PDF pages).
- [ ] **Day 11:** Build re-OCR pipeline on redacted images and PDF pages to extract post-redaction visual text.
- [ ] **Day 12:** Optimize re-OCR pipeline for speed and high-precision residual detection.
- [ ] **Day 13:** Flag low-confidence OCR text regions as security review events.
- [ ] **Day 17:** Test rotated images (90°/180°) and noisy scans against OCR preprocessor.
- [ ] **Day 18:** Generate visual before-and-after comparison images for presentation.
- [ ] **Day 21:** Finalize image processing documentation and figures.

---

## 3. Developer 3: PII Detection & Context Engine Lead

### ⏳ Tasks Left to be Done
- [ ] **Day 1:** Establish `src/schema/entities.py` and research Presidio/spaCy configurations.
- [ ] **Day 2:** Build core deterministic regexes in `src/detection/regex.py` (email, phone, SSN).
- [ ] **Day 3:** Add national/financial IDs to regex (PAN, Aadhaar, Passports, Cards, Employee IDs).
- [ ] **Day 4:** Integrate spaCy and Microsoft Presidio in `src/detection/ner.py` for names and locations.
- [ ] **Day 5:** Run baseline regex + NER across extracted text; identify edge misses.
- [ ] **Day 6:** Build `src/detection/context.py` (window cue detector + table header context injector).
- [ ] **Day 6:** Implement `src/detection/validators.py` (Luhn checksum, Verhoeff, libphonenumbers).
- [ ] **Day 7:** Implement `src/detection/resolver.py` (merge overlapping regex + NER + context spans).
- [ ] **Day 8:** Build narrative prose context triggers (section headings modifying confidence).
- [ ] **Day 9:** Refine false-positive rejection using allow-lists.
- [ ] **Day 10:** Add support for Indian identifiers (PAN, GST, IFSC, UPI) with context rules.
- [ ] **Day 11:** Profile detection recall specifically on Page 22 (Risk Policy PDF).
- [ ] **Day 12:** Build digit-run heuristics, entropy checkers, and alternate regex for verifier feed.
- [ ] **Day 13:** Validate span resolution on adversarial spaced tokens (`R a h u l`).
- [ ] **Day 15:** Tune context confidence weights (`confidence = 0.3*regex + 0.25*NER + 0.15*context + ...`).
- [ ] **Day 16:** Finalize allow-list patterns based on baseline false-positive analysis.
- [ ] **Day 17:** Run adversarial test suite against detector (homoglyphs, spacing, zero-width chars).
- [ ] **Day 21:** Finalize taxonomy, regex documentation, and Presidio customization guide.

---

## 4. Developer 4: Security Policy, Independent Verification & Audit Lead

### ⏳ Tasks Left to be Done
- [ ] **Day 1:** Draft threat model, initial `config/policy.yaml`, and security boundary specs.
- [ ] **Day 3:** Implement business reference allow-lists (`INC-*`, `RSK-*`, `GRP-POL-*`).
- [ ] **Day 4:** Draft risk scoring rubric in `src/policy/risk.py` (Critical, High, Medium).
- [ ] **Day 5:** Implement audit logging schema (salted hash structure) in `src/audit/logger.py`.
- [ ] **Day 7:** Connect entity resolution with policy lookup (`action: REDACT/BLOCK/ALLOW`).
- [ ] **Day 8:** Implement `src/policy/policy.py` reading `config/policy.yaml` and MAX-risk aggregation.
- [ ] **Day 9:** Build `src/sanitization/text_redactor.py` (`[REDACTED_TYPE]` or solid block masking).
- [ ] **Day 10:** Reconstruct sanitized PDFs with opaque burned boxes (`src/sanitization/pdf_redactor.py`).
- [ ] **Day 11:** Connect re-OCR output to secondary scan feed in `src/verification/residual_scan.py`.
- [ ] **Day 12:** Implement `src/verification/verifier.py` (independent stack decoupled from primary detector).
- [ ] **Day 13:** Implement `src/verification/gate.py` (`AI_READY = TRUE` only if verifier passes and no critical uncertainty remains).
- [ ] **Day 15:** Audit compliance verification (confirm zero raw PII logged anywhere in runtime).
- [ ] **Day 16:** Verify security boundary behavior under simulated detector failures.
- [ ] **Day 17:** Verify prompt injection handling (confirm injected prompts inside text are treated as inert data).
- [ ] **Day 18:** Implement output scanner on LLM responses (second security boundary).
- [ ] **Day 19:** Display Gate decision (`AI READY: PASS / BLOCK`), audit logs, and policy toggles in UI.
- [ ] **Day 21:** Complete `docs/threat_model.md`, security boundary writeup, and policy guide.

---

## 5. Developer 5: Evaluation Benchmark, Adversarial Testing & UI Lead

### ⏳ Tasks Left to be Done
- [ ] **Day 1:** Catalog the 3 supplied artifacts (pages, images, tables, text boxes, notes, metadata).
- [ ] **Day 2:** Create annotation format schema in `data/ground_truth/annotation_spec.json`.
- [ ] **Day 3:** Begin ground-truth manual span annotation on Risk Policy PDF (Pages 1, 18, 22).
- [ ] **Day 4:** Annotate ground-truth for TPRM DOCX and Org Pack PPTX.
- [ ] **Day 5:** Complete and freeze Ground Truth annotations for all 3 Cadence documents.
- [ ] **Day 6:** Build initial evaluation span matcher in `src/evaluation/matcher.py` (overlap threshold / IoU).
- [ ] **Day 7:** Run Day 7 evaluation benchmark on Week 1 detection pipeline.
- [ ] **Day 8:** Generate initial synthetic dataset (controlled PII: names, emails, passports, synthetic SSNs).
- [ ] **Day 9:** Build metric calculation engine `src/evaluation/metrics.py` (Precision, Recall, F1, Over-redaction).
- [ ] **Day 10:** Generate held-out evaluation dataset (strictly separated from development tuning).
- [ ] **Day 11:** Build automated test harness for synthetic evaluation (`src/evaluation/benchmark.py`).
- [ ] **Day 12:** Design adversarial test cases (zero-width characters, homoglyphs, rotated text, tiny fonts).
- [ ] **Day 13:** Run full pipeline test on deliberate leak injections (asserting verifier catches and blocks).
- [ ] **Day 15:** Finalize `data/heldout/` frozen test suite; lock test split forever.
- [ ] **Day 16:** Run formal ablation study (`Baseline` vs `Improved`) and record metrics in `reports/evaluation/`.
- [ ] **Day 17:** Generate adversarial robustness report and confusion matrices.
- [ ] **Day 18:** Execute 20-question Utility Evaluation comparing answers from original vs. sanitized documents.
- [ ] **Day 19:** Build Streamlit app layout (`app.py`), upload screen, review queue, and download buttons.
- [ ] **Day 20:** Run 4 showcase end-to-end demos on Cadence artifacts.
- [ ] **Day 21:** Complete `docs/evaluation.md`, compile presentation slide deck, and conduct demo.

---

## 6. Milestone Progress Summary

| Role / Module | Assigned Days | Current Status | Completion % |
|---|---|---|---|
| **Developer 1: Lead Architect** | Days 1–7 (W1), Days 8–11 (W2), Days 15–21 (W3) | **Week 1 Core Complete & Frozen** | **100% of W1 Deliverables** |
| **Developer 2: OCR & Vision** | Days 1–7 (W1), Days 8–13 (W2), Days 15–21 (W3) | Pending OCR Adapter & Pixel Redaction | 0% |
| **Developer 3: PII Detection** | Days 1–7 (W1), Days 8–13 (W2), Days 15–21 (W3) | Pending Regex Catalog & Presidio NER | 0% |
| **Developer 4: Policy & Verifier**| Days 1–7 (W1), Days 8–13 (W2), Days 15–21 (W3) | Pending Policy YAML & Fail-Closed Gate | 0% |
| **Developer 5: Benchmark & UI** | Days 1–7 (W1), Days 8–13 (W2), Days 15–21 (W3) | Pending Ground Truth & Streamlit UI | 0% |
