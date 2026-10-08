# Product Requirements Document (PRD) & Implementation Plan
## PII Security Firewall for Cadence (Optiv Consulting Case Study 2)

**Duration:** 3 Weeks (21 Days)  
**Product Type:** Local / Approved-Environment AI Security Gateway  
**Primary Goal:** Prevent Personally Identifiable Information (PII) from reaching downstream AI/LLM systems by detecting, sanitizing, independently verifying, and strictly controlling document flow with a fail-closed architecture.

---

## 1. Executive Summary & Vision

The **PII Security Firewall** is an OCR-first, multimodal, fail-closed security gateway. Rather than directly streaming enterprise documents into an LLM assistant, the gateway sits inline:
```
User Uploads File 
       │
       ▼
File Validation & Security Checks (Limits, MIME, Archive Safety)
       │
       ▼
Document Extraction (Native text, OCR, images/screenshots, tables, metadata)
       │
       ▼
PII Detection Layer (Regex, NER, Context, Structure, Validators)
       │
       ▼
Entity Resolution + Deduplication
       │
       ▼
Risk & Policy Engine ───[BLOCK]───► Disallowed / Alert
       │
   [REDACT]
       ▼
Sanitized Document Generation (Text redaction + True pixel burning)
       │
       ▼
Independent Verification (Heterogeneous secondary detection & Re-OCR)
       │
   ┌───┴───┐
[PASS]   [FAIL] ──► BLOCK (Uncertain / Leak detected)
   │
   ▼
AI READY (Allowed to pass to Local/Approved LLM)
```

### Core Security Philosophy
- **OCR-First:** OCR is not a fallback. Every page is treated as potentially containing visual PII (scanned forms, stamps, screenshots, org charts).
- **Defense in Depth:** No single detector is trusted. Detection couples Regex + NER + Context Rules + Document Structure + Algorithmic Validators.
- **Independent Verification:** The verifier runs a different detection stack than the primary detector. A detector missing an entity should not have its blind spot repeated by its own verifier.
- **Fail Closed:** If confidence is low, extraction fails, or verification is uncertain $\rightarrow$ **BLOCK**. Unknown is unsafe.
- **Redaction by Default:** Inherent PII is redacted directly. Pseudonymization mappings are high-risk sensitive assets and secondary to the 3-week MVP.

---

## 2. Supported Inputs & Artifact Challenges

| Artifact / Format | Structure Characteristics | Key Challenge & Focus |
|---|---|---|
| **Risk Policy PDF** | 35-page scanned PDF, 220-dpi JPEG pages, zero native text layer. | Must OCR every page. Page 22 has dense narrative prose PII (names, SSN, DOB, passports, PAN, home address). |
| **TPRM Training DOCX** | ~82 pages, ~38 embedded OneTrust screenshots, 16 tables, 4 text boxes. | Embedded screenshot extraction, OCR on images, table header context resolution. |
| **Org Pack PPTX** | 9 slides, native shapes, org charts, speaker notes, hidden slides. | Small text inside diagrams, visual organization hierarchy, hidden channels/notes. |

---

## 3. PII Taxonomy & Detection Architecture

### 3.1 PII Taxonomy
- **Identity:** `PERSON`, `DOB`, `ADDRESS`
- **Contact:** `EMAIL`, `PHONE`
- **Organization IDs:** `EMPLOYEE_ID`, `DIRECTOR_ID`
- **National / Govt IDs:** `SSN`, `PASSPORT`, `PAN`, `TAX_ID`, `AADHAAR`, `NINO`
- **Financial:** `CARD`, `BANK_ACCOUNT`, `IFSC`, `GST`, `UPI`
- **Visual Signals:** `SIGNATURE`, `FACE/PHOTO`, `SENSITIVE_SCREENSHOT`
- **Allow-list (False-Positive Prevention):** Business codes such as `INC-\d{4}-\d+`, `RSK-\d+`, `GRP-POL-\d+`, `CTL-IAM-\d+`.

### 3.2 Detection Layers & Confidence Scoring
1. **Layer 1: Regex Engine:** Deterministic patterns for email, phone, SSN, PAN, Aadhaar, cards, standard employee IDs.
2. **Layer 2: Local NER Engine:** Presidio + spaCy NER for unstructured narrative names, locations, and organizations.
3. **Layer 3: Context Engine:** Sliding window token cues (`"SSN:"`, `"DOB:"`), table header inheritance (`Emp ID` $\rightarrow$ cell values), and document-level section triggers (`"Employee Personal Information"`).
4. **Layer 4: Validators:** Algorithmic checks (Luhn, Verhoeff, libphonenumbers) modify confidence without discarding non-standard synthetic data.
5. **Layer 5: Entity Resolver:** Overlapping span merging and conflict resolution into a unified schema.

```json
{
  "entity_id": "urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "type": "EMAIL",
  "source": "ocr",
  "value_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "page": 18,
  "bbox": [120, 450, 310, 490],
  "text_start": 1203,
  "text_end": 1225,
  "confidence": 0.97,
  "risk": "HIGH",
  "action": "REDACT"
}
```

---

## 4. 5-Person Team Structure & Responsibilities

To achieve equal division of work and avoid sequential bottlenecks, the team divides into 5 parallel modules around frozen contracts and schemas.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Person 1: Lead Architect                        │
│               Ingestion, Dispatcher & Multimodal Extraction            │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Raw Blocks, Spans & Images
┌──────────────────────────────────┴─────────────────────────────────────┐
│                        Person 2: OCR & Vision Lead                     │
│                OCR Pipelines, Bounding Boxes & Pixel Redactor          │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Extracted OCR Text + Bounding Boxes
┌──────────────────────────────────┴─────────────────────────────────────┐
│                      Person 3: PII Detection Lead                      │
│            Regex, Spacy/Presidio NER, Context & Entity Resolution       │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Unified PII Entities & Risk Tags
┌──────────────────────────────────┴─────────────────────────────────────┐
│                    Person 4: Security Policy & Verifier                │
│       Policy Engine, Secondary Verifier, Audit Log & Fail-Closed Gate  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Sanitized Artifacts & Pass/Block State
┌──────────────────────────────────┴─────────────────────────────────────┐
│                   Person 5: Evaluation, Benchmark & UI                 │
│         Synthetic/Adversarial Datasets, Benchmark Metrics & Streamlit  │
└────────────────────────────────────────────────────────────────────────┘
```

### Detailed Person Profiles

#### **Person 1: Multimodal Ingestion & Dispatcher Lead**
- **Domain:** File safety, document parsing, structural extraction, metadata stripping.
- **Key Modules:** `src/ingestion/validators.py`, `src/ingestion/dispatcher.py`, `src/ingestion/pdf.py`, `src/ingestion/docx.py`, `src/ingestion/pptx.py`, `src/ingestion/metadata.py`, `src/security/limits.py`, `src/schema/document.py`.
- **Primary Deliverables:**
  - Robust readers for PDF (`pdfplumber`/`pypdf`), DOCX (`python-docx`, `zipfile`), and PPTX (`python-pptx`).
  - Deep screenshot, shape, table, and metadata extraction (author, notes, hidden slides, alt-text).
  - Pre-processing file safety (zip bomb guards, malformed XML limits, MIME inspection).
  - Common unified document format representation (`CanonicalDocument`).

#### **Person 2: OCR Engine & Image Redaction Lead**
- **Domain:** Image preprocessing, OCR inference, bounding-box coordinate tracking, true pixel redaction.
- **Key Modules:** `src/ocr/engine.py`, `src/ocr/preprocess.py`, `src/ocr/regions.py`, `src/ocr/confidence.py`, `src/sanitization/image_redactor.py`, `src/sanitization/pdf_redactor.py`.
- **Primary Deliverables:**
  - Local OCR benchmarking (`PaddleOCR` vs `EasyOCR`) and resolution enhancement (220-dpi upscaling).
  - Text-region bounding box generation with character-level and word-level coordinates.
  - Low-confidence OCR detection tagging (for fail-closed triggering).
  - Pixel-masking redactor that permanently burns black opaque boxes into image pixels (preventing layer recovery).
  - DOCX/PPTX embedded image replacement and reconstructed sanitized PDFs.

#### **Person 3: PII Detection & Context Engine Lead**
- **Domain:** Rule-based patterns, machine learning NER, document-level and table-level context reasoning.
- **Key Modules:** `src/detection/regex.py`, `src/detection/ner.py`, `src/detection/context.py`, `src/detection/validators.py`, `src/detection/resolver.py`, `src/schema/entities.py`.
- **Primary Deliverables:**
  - Regex catalog for national IDs (SSN, PAN, Aadhaar, Passport), contact info, cards, employee IDs.
  - Local spaCy & Microsoft Presidio integration for narrative names, addresses, and organizations.
  - Context engine: sliding cue windows (`"SSN:"`), table column-header propagation, and document-level section cues.
  - Validation routines (Luhn, Verhoeff, international phone validation).
  - Overlapping span resolver and unified deduplicator.

#### **Person 4: Security Policy, Independent Verification & Audit Lead**
- **Domain:** Policy enforcement, risk scoring, independent verification boundary, zero-PII audit logging.
- **Key Modules:** `src/policy/risk.py`, `src/policy/policy.py` (`config/policy.yaml`), `src/sanitization/text_redactor.py`, `src/verification/verifier.py`, `src/verification/residual_scan.py`, `src/verification/gate.py`, `src/audit/logger.py`.
- **Primary Deliverables:**
  - YAML-driven policy engine (`REDACT`, `BLOCK`, `ALLOW` with business allow-lists).
  - Inherent risk vs. residual risk scoring (critical entity dominance rule).
  - Native text redactor (`[REDACTED_TYPE]` or solid block masking).
  - **Independent Verifier:** A decoupled detection stack (secondary regex + alternate NER + digit-run entropy) checking re-OCRed sanitized artifacts.
  - Fail-closed gate: `AI_READY = TRUE` only upon strict zero unresolved high-risk detections.
  - Salted hash audit log (recording entity type, coordinate, hash, and outcome—never raw text).

#### **Person 5: Evaluation Benchmark, Adversarial Testing & UI Lead**
- **Domain:** Ground truth annotation, synthetic data generation, metrics calculation, and Streamlit user experience.
- **Key Modules:** `src/evaluation/matcher.py`, `src/evaluation/metrics.py`, `src/evaluation/benchmark.py`, `src/evaluation/ablation.py`, `app.py`, `tests/adversarial/`.
- **Primary Deliverables:**
  - Frozen Ground Truth dataset and synthetic document generator (international names, IDs, edge cases).
  - Adversarial suite (zero-width spaces, character spacing, homoglyphs, rotated text, blurry scans).
  - Formal evaluation suite: Recall, Precision, F1, Risk-Weighted Recall, Document Leak Rate, and Over-Redaction rate.
  - Baseline vs. Context-Enhanced ablation experiment (proving research claims).
  - Interactive Streamlit dashboard showing original page, bounding boxes, sanitized page, verification status, and AI Readiness gate.

---

## 5. Step-by-Step 3-Week (21-Day) Implementation Roadmap

```
WEEK 1: Architecture, Extraction, Freezing & Core Detection
├── Day 1:  Environment, Sample Inspection, Common Schema & Base Architecture
├── Day 2:  PDF Extraction & OCR Benchmarking
├── Day 3:  DOCX Extraction (38 screenshots & tables) & Regex Catalog
├── Day 4:  PPTX Extraction & NER Integration
├── Day 5:  FREEZE EXTRACTOR CHECKPOINT & Ground Truth Annotation Start
├── Day 6:  Context Engine & Checksum Validators
└── Day 7:  Week 1 Integration Review & Entity Resolver Benchmark

WEEK 2: Security Pipeline, Redaction & Independent Verification
├── Day 8:  Policy Engine & Inherent Risk Model (config/policy.yaml)
├── Day 9:  Text Redaction Engine & Native Document Reconstruction
├── Day 10: Image Pixel Masking & PDF/DOCX Image Replacement
├── Day 11: Re-OCR Engine for Sanitized Artifacts
├── Day 12: Independent Verifier Engine (Secondary Stack)
├── Day 13: Fail-Closed Gate & Zero-PII Audit Logger
└── Day 14: Week 2 Integration Review & End-to-End Pipeline Smoke Test

WEEK 3: Evaluation, Adversarial Suite, UI & Final Delivery
├── Day 15: Synthetic Dataset Generation & Frozen Held-Out Test Splits
├── Day 16: Benchmark Execution (Baseline vs. Context-Enhanced Ablation)
├── Day 17: Adversarial Attack Suite & Evasion Testing
├── Day 18: LLM Utility Evaluation (20 Q&A consistency & degradation tests)
├── Day 19: Streamlit Security Checkpoint Dashboard
├── Day 20: Full End-to-End Testing on 3 Cadence Artifacts
└── Day 21: Documentation, Threat Model, Architecture Diagrams & Final Demo
```

### Day-by-Day Task Breakdown

#### **Week 1: Extraction & Detection Foundations**
- **Day 1 (All): Kickoff & Alignment**
  - **P1:** Set up repo layout, git hooks, virtual environment, and initial `src/schema/document.py`.
  - **P2:** Verify OCR engines (`PaddleOCR` vs `EasyOCR`) on local GPU/CPU; inspect 35-page Risk Policy PDF.
  - **P3:** Establish `src/schema/entities.py` and research Presidio/spaCy configurations.
  - **P4:** Draft threat model, initial `config/policy.yaml`, and security boundary specs.
  - **P5:** Catalog the 3 supplied artifacts (pages, images, tables, text boxes, notes, metadata).
- **Day 2: PDF Parsing & OCR Engine**
  - **P1:** Build `src/ingestion/pdf.py` (detect native vs scanned pages, extract annotations).
  - **P2:** Implement `src/ocr/engine.py` and `src/ocr/preprocess.py` (contrast/binarization, 220-dpi handling).
  - **P3:** Build core deterministic regexes in `src/detection/regex.py` (email, phone, SSN).
  - **P4:** Define security input validation in `src/security/limits.py` (file size, zip expansion limit).
  - **P5:** Create annotation format schema in `data/ground_truth/annotation_spec.json`.
- **Day 3: DOCX Processing & Regex Expansion**
  - **P1:** Implement `src/ingestion/docx.py` (extract paragraphs, 16 tables, 4 text boxes, and 38 screenshots).
  - **P2:** Extract and test OCR on all 38 OneTrust screenshots.
  - **P3:** Add national/financial IDs to regex (PAN, Aadhaar, Passports, Cards, Employee IDs).
  - **P4:** Implement business reference allow-lists (`INC-*`, `RSK-*`, `GRP-POL-*`).
  - **P5:** Begin ground-truth manual span annotation on Risk Policy PDF (Page 1, 18, 22).
- **Day 4: PPTX Processing & NER Integration**
  - **P1:** Implement `src/ingestion/pptx.py` and `src/ingestion/metadata.py` (slide shapes, notes, hidden slides, metadata).
  - **P2:** Build `src/ocr/regions.py` for bounding-box extraction and coordinate normalization.
  - **P3:** Integrate spaCy and Microsoft Presidio in `src/detection/ner.py` for names and locations.
  - **P4:** Draft risk scoring rubric in `src/policy/risk.py` (Critical, High, Medium).
  - **P5:** Annotate ground-truth for TPRM DOCX and Org Pack PPTX.
- **Day 5: CRITICAL CHECKPOINT - Freeze Extractor & Ground Truth**
  - **P1:** Lock `CanonicalDocument` schema and freeze all extraction code.
  - **P2:** Freeze image extraction and OCR coordinates so annotations do not drift.
  - **P3:** Run baseline regex + NER across extracted text; identify edge misses.
  - **P4:** Implement audit logging schema (salted hash structure) in `src/audit/logger.py`.
  - **P5:** Complete and freeze Ground Truth annotations for all 3 Cadence documents.
- **Day 6: Context Engine & Validators**
  - **P1:** Implement unified dispatcher `src/ingestion/dispatcher.py` tying PDF, DOCX, and PPTX together.
  - **P2:** Implement OCR confidence scoring in `src/ocr/confidence.py` (flagging low-confidence characters).
  - **P3:** Build `src/detection/context.py` (window cue detector + table header context injector).
  - **P4:** Implement `src/detection/validators.py` (Luhn checksum, Verhoeff, libphonenumbers).
  - **P5:** Build initial evaluation span matcher in `src/evaluation/matcher.py` (overlap threshold / IoU).
- **Day 7: Entity Resolution & Week 1 Wrap-up**
  - **P1:** Unit tests for all document extractors and edge-case handling.
  - **P2:** Benchmark OCR latency across sample pages and optimize memory use.
  - **P3:** Implement `src/detection/resolver.py` (merge overlapping regex + NER + context spans).
  - **P4:** Connect entity resolution with policy lookup (`action: REDACT/BLOCK/ALLOW`).
  - **P5:** Run Day 7 evaluation benchmark on Week 1 detection pipeline.

---

#### **Week 2: Security Pipeline, Redaction & Independent Verification**
- **Day 8: Policy Engine & Risk Aggregation**
  - **P1:** Implement document structure retention trackers (heading and layout metadata).
  - **P2:** Build bounding-box coordinate transformer for image replacement.
  - **P3:** Build narrative prose context triggers (e.g. section headings modifying confidence).
  - **P4:** Implement `src/policy/policy.py` reading `config/policy.yaml` and MAX-risk aggregation.
  - **P5:** Generate initial synthetic dataset (controlled PII: names, emails, passports, synthetic SSNs).
- **Day 9: Text Redaction & Document Sanitization**
  - **P1:** Implement native DOCX text replacement and reconstructed XML packing.
  - **P2:** Build image mask bounding-box calculator with safety padding.
  - **P3:** Refine false-positive rejection using allow-lists.
  - **P4:** Build `src/sanitization/text_redactor.py` (`[REDACTED_TYPE]` or solid block masking).
  - **P5:** Build metric calculation engine `src/evaluation/metrics.py` (Precision, Recall, F1, Over-redaction).
- **Day 10: Image Pixel Redactor & Reconstruction**
  - **P1:** Rebuild sanitized DOCX containing redacted replacement images.
  - **P2:** Implement `src/sanitization/image_redactor.py` (permanent pixel burning with OpenCV/Pillow).
  - **P3:** Add support for Indian identifiers (PAN, GST, IFSC, UPI) with context rules.
  - **P4:** Reconstruct sanitized PDFs with opaque burned boxes (`src/sanitization/pdf_redactor.py`).
  - **P5:** Generate held-out evaluation dataset (strictly separated from development tuning).
- **Day 11: Re-OCR Sanitization Loop**
  - **P1:** Implement sanitized file open-and-read integrity check (fail-closed if corrupted).
  - **P2:** Build re-OCR pipeline on redacted images and PDF pages to extract post-redaction visual text.
  - **P3:** Profile detection recall specifically on Page 22 (Risk Policy PDF).
  - **P4:** Connect re-OCR output to secondary scan feed in `src/verification/residual_scan.py`.
  - **P5:** Build automated test harness for synthetic evaluation.
- **Day 12: Independent Verifier Implementation (Security Boundary)**
  - **P1:** Sanitize metadata, comments, and speaker notes (`src/ingestion/metadata.py`).
  - **P2:** Optimize re-OCR pipeline for speed and high-precision residual detection.
  - **P3:** Build digit-run heuristics, entropy checkers, and alternate regex for the verifier.
  - **P4:** Implement `src/verification/verifier.py` (independent stack decoupled from primary detector).
  - **P5:** Design adversarial test cases (zero-width characters, homoglyphs, rotated text, tiny fonts).
- **Day 13: Fail-Closed Gate & Audit Logging**
  - **P1:** Ensure complete error handling across all parsers (unsupported formats $\rightarrow$ safe error).
  - **P2:** Flag low-confidence OCR text regions as security review events.
  - **P3:** Validate span resolution on adversarial spaced tokens (`R a h u l`).
  - **P4:** Implement `src/verification/gate.py` (`AI_READY = TRUE` only if verifier passes and no critical uncertainty remains).
  - **P5:** Run full pipeline test on deliberate leak injections (asserting verifier catches and blocks).
- **Day 14: Week 2 Integration & End-to-End Smoke Test**
  - **P1–P5 Joint Review:** Execute full pipeline from Raw File $\rightarrow$ Extraction $\rightarrow$ Detection $\rightarrow$ Redaction $\rightarrow$ Re-OCR $\rightarrow$ Verification $\rightarrow$ Gate $\rightarrow$ Audit Log.

---

#### **Week 3: Evaluation, Adversarial Suite, UI & Final Delivery**
- **Day 15: Synthetic Dataset & Frozen Split Finalization**
  - **P1:** Stress test file ingestion with large documents and edge archives.
  - **P2:** Verify image redaction quality across complex charts and stamps (Figure 8).
  - **P3:** Tune context confidence weights (`confidence = 0.3*regex + 0.25*NER + 0.15*context + ...`).
  - **P4:** Audit compliance verification (confirm zero raw PII logged anywhere in runtime).
  - **P5:** Finalize `data/heldout/` frozen test suite; lock test split forever.
- **Day 16: Core Experiment & Benchmark Ablation**
  - **P1:** Monitor memory and execution limits under full test load.
  - **P2:** Assist in running batch OCR across the held-out benchmark.
  - **P3:** Finalize allow-list patterns based on baseline false positive analysis.
  - **P4:** Verify security boundary behavior under simulated detector failures.
  - **P5:** Run formal ablation study (`Baseline [OCR + Regex + NER]` vs `Improved [+ Context + Structure + Allow-list + Verification]`) and record all metrics in `reports/evaluation/`.
- **Day 17: Adversarial Suite & Security Validation**
  - **P1:** Test input validation against corrupt zips, XML bombs, and path traversals.
  - **P2:** Test rotated images (90°/180°) and noisy scans against OCR preprocessor.
  - **P3:** Run adversarial test suite against detector (homoglyphs, spacing, zero-width chars).
  - **P4:** Verify prompt injection handling (confirm injected prompts inside text are treated as inert data).
  - **P5:** Generate adversarial robustness report and confusion matrices.
- **Day 18: LLM Utility Experiment & Mock/Local LLM**
  - **P1:** Ensure sanitized documents maintain $\ge 80\%$ structural formatting.
  - **P2:** Generate visual before-and-after comparison images for presentation.
  - **P3:** Set up mock/local LLM endpoint for demonstration.
  - **P4:** Implement output scanner on LLM responses (second security boundary).
  - **P5:** Execute 20-question Utility Evaluation comparing answers from original vs. sanitized documents.
- **Day 19: Streamlit Security Dashboard**
  - **P1:** Connect document upload and status callbacks to UI.
  - **P2:** Render bounding boxes and visual side-by-side page comparisons in UI.
  - **P3:** Connect entity breakdown counters to UI.
  - **P4:** Display Gate decision (`AI READY: PASS / BLOCK`), audit logs, and policy toggles.
  - **P5:** Build Streamlit app layout (`app.py`), upload screen, review queue, and download buttons.
- **Day 20: Comprehensive End-to-End Testing on Cadence Artifacts**
  - **P1–P5 Joint Testing:** Run all 4 showcase demos:
    1. **Demo 1:** Scanned Risk Policy PDF (Page 22 narrative PII, 35 pages OCRed, burned redactions, AI Ready).
    2. **Demo 2:** DOCX OneTrust screenshots (visual PII redacted from pixels where text parser saw nothing).
    3. **Demo 3:** Deliberate attack (primary detector misses adversarial PII, independent verifier catches $\rightarrow$ BLOCKED).
    4. **Demo 4:** False positive handling (`INC-2026-0417` preserved by allow-list $\rightarrow$ ALLOWED).
- **Day 21: Final Documentation, Architecture Artifacts & Presentation**
  - **P1:** Complete `docs/architecture.md` and repository setup instructions in `README.md`.
  - **P2:** Finalize image processing documentation and figures.
  - **P3:** Finalize taxonomy, regex documentation, and Presidio customization guide.
  - **P4:** Complete `docs/threat_model.md`, security boundary writeup, and policy guide.
  - **P5:** Complete `docs/evaluation.md`, compile presentation slide deck, and conduct dry run.

---

## 6. Target Performance & Acceptance Metrics

| Metric | Target | Measurement Method |
|---|---|---|
| **Critical PII Recall** (SSN, Passport, PAN, Cards, Aadhaar) | $\ge 99\%$ | $TP / (TP + FN)$ on frozen held-out test set |
| **High-Risk PII Recall** (Email, Phone, Address, DOB, Emp ID) | $\ge 99\%$ | $TP / (TP + FN)$ on frozen held-out test set |
| **Overall PII Recall** | $\ge 95\%$ | $TP / (TP + FN)$ across all entity types |
| **Document Leak Rate** | **0** | Leaky documents / total held-out documents (0 allowed) |
| **Over-Redaction Rate** | $< 10\%$ | False redactions / total redactions |
| **Structure Retention** | $\ge 80\%$ | Preserved structural elements / original elements |
| **Low-Confidence Critical Pass** | **0 (Strict Fail-Closed)** | Low-confidence critical regions allowed without block |
| **Verifier Failures Incorrectly Allowed** | **0 (Strict Fail-Closed)** | Verifier residual alert bypassed |

---

## 7. Recommended Repository Directory Layout

```text
pii-security-firewall/
├── app.py                      # Streamlit Security Gateway UI
├── README.md                   # Setup, architecture & run instructions
├── requirements.txt            # Python dependencies (presidio, spacy, easyocr/paddleocr, etc.)
├── Dockerfile                  # Local containerized gateway build
├── config/
│   └── policy.yaml             # Risk levels, actions, allow-lists
├── src/
│   ├── ingestion/              # [Person 1]
│   │   ├── validators.py       # File format & size safety
│   │   ├── dispatcher.py       # Multi-format router
│   │   ├── pdf.py              # PDF native & scanned page reader
│   │   ├── docx.py             # DOCX parser (tables, text boxes, images)
│   │   ├── pptx.py             # PPTX parser (shapes, notes, hidden slides)
│   │   └── metadata.py         # Metadata & hidden content extractor
│   ├── ocr/                    # [Person 2]
│   │   ├── engine.py           # OCR engine adapter (PaddleOCR / EasyOCR)
│   │   ├── preprocess.py       # Image binarization & upscaling
│   │   ├── regions.py          # Bounding-box coordinate generator
│   │   └── confidence.py       # Character & word confidence scoring
│   ├── schema/                 # [All / P1 Lead]
│   │   ├── document.py         # Canonical document object models
│   │   └── entities.py         # PII entity schema & audit models
│   ├── detection/              # [Person 3]
│   │   ├── regex.py            # High-precision deterministic patterns
│   │   ├── ner.py              # Local Presidio + spaCy NER
│   │   ├── context.py          # Sliding cue window & table header context
│   │   ├── validators.py       # Luhn, Verhoeff & format checksums
│   │   └── resolver.py         # Span deduplication & conflict resolver
│   ├── policy/                 # [Person 4]
│   │   ├── risk.py             # Inherent vs residual risk scoring
│   │   └── policy.py           # Policy rules, actions & allow-lists
│   ├── sanitization/           # [Person 2 & 4]
│   │   ├── text_redactor.py    # Native text replacement
│   │   ├── image_redactor.py   # True pixel burning on images
│   │   └── pdf_redactor.py     # Burned redactions on scanned PDF pages
│   ├── verification/           # [Person 4]
│   │   ├── verifier.py         # Independent secondary detector stack
│   │   ├── residual_scan.py    # Re-OCR scan on sanitized output
│   │   └── gate.py             # Fail-closed AI Readiness gate
│   ├── audit/                  # [Person 4]
│   │   └── logger.py           # Salted-hash, zero-PII audit logging
│   ├── evaluation/             # [Person 5]
│   │   ├── matcher.py          # Bounding-box IoU & text span matcher
│   │   ├── metrics.py          # Recall, precision, F1, leak rate
│   │   ├── benchmark.py        # Automated test harness
│   │   └── ablation.py         # Baseline vs. context experiment
│   └── security/               # [Person 1 & 4]
│       ├── limits.py           # Decompression & memory limits
│       └── input_safety.py     # Prompt injection isolation
├── data/
│   ├── raw/                    # 3 supplied Cadence documents
│   ├── synthetic/              # Generated test documents
│   ├── ground_truth/           # Frozen ground-truth annotations
│   ├── heldout/                # Never-tuned test set
│   └── outputs/                # Sanitized documents & audit trails
├── tests/
│   ├── unit/                   # Component tests
│   ├── integration/            # Pipeline tests
│   ├── adversarial/            # Evasion attack tests
│   └── regression/             # CI regression checks
├── reports/
│   ├── evaluation/             # Benchmark metrics & ablation tables
│   ├── figures/                # Visual comparison charts
│   └── logs/                   # Execution logs
└── docs/
    ├── architecture.md         # System design & data flow
    ├── threat_model.md         # Threat actors & mitigations
    └── evaluation.md           # Empirical benchmark results
```
