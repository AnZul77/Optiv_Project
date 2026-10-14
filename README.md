# PII Security Firewall (Optiv Case Study)

**An OCR-First, Multimodal, Fail-Closed Security Gateway for Enterprise AI Ingestion**

The **PII Security Firewall** is a local and approved-environment AI Security Gateway designed to prevent Personally Identifiable Information (PII) from reaching downstream Large Language Models (LLMs). Operating inline between enterprise document repositories and AI systems, it detects, sanitizes, independently verifies, and strictly controls document flow.

If any detection confidence is low, extraction fails, or post-redaction verification detects residual signals, the document is **BLOCKED**.

---

## Architecture Overview

```
User Uploads File (PDF, DOCX, PPTX)
        │
        ▼
[1] Pre-Flight Security & Validation (Limits, MIME, Magic Bytes, Zip Bomb Safety)
        │
        ▼
[2] Multimodal Extraction (Native text, 220-DPI OCR Rendering, Screenshots, Tables, Metadata)
        │
        ▼
[3] Multi-Layer PII Detection (Regex, Presidio/spaCy NER, Context Cues, Checksum Validators)
        │
        ▼
[4] Entity Resolution & Conflict Deduplication
        │
        ▼
[5] Policy & Inherent Risk Engine ───[BLOCK]───► Disallowed / Alert (Fail-Closed)
        │
   [REDACT]
        ▼
[6] Sanitized Document Reconstruction (Native Word/PDF text replacement + True pixel burning)
        │
        ▼
[7] Independent Verification (Heterogeneous secondary detector + Re-OCR residual scan)
        │
   ┌────┴────┐
 [PASS]    [FAIL] ──► BLOCK (Residual leak / Uncertainty detected)
   │
   ▼
[8] AI READY (Enclosed in inert data envelope, released to Local/Approved LLM)
```

---

## Core Security Principles

- **OCR-First**: OCR is not a fallback. Every page is treated as potentially containing visual PII (scanned forms, stamps, screenshots, org charts).
- **Defense in Depth**: Detection couples 5 layers: Deterministic Regex + Machine Learned NER + Contextual Cue Windows + Algorithmic Validators + Entity Resolution.
- **Independent Verification**: The verifier runs a **different** detection stack than the primary detector. A detector's blind spot is never verified by its own logic.
- **Fail Closed**: If confidence is low ($\le 0.60$), extraction encounters an error, or verification is uncertain $\rightarrow$ **BLOCK**. Unknown is unsafe.
- **Zero-PII Audit Trail**: Logs record entity types, coordinates, actions, and salted SHA-256 hashes (`value_hash`). Plaintext PII is **never** written to logs.

---

## Supported Artifact Challenges

| Artifact | Structure Characteristics | Key Challenge & Focus |
|---|---|---|
| **Risk Policy PDF** | 35-page scanned PDF, 220-DPI JPEG pages, zero native text layer | High-resolution 220-DPI page rendering; dense narrative prose PII on Page 22 (names, SSN, DOB, passports, PAN). |
| **TPRM Training DOCX** | ~82 pages, ~38 embedded OneTrust screenshots, 16 tables, 4 text boxes | Embedded screenshot extraction, OpenXML text boxes (`w:txbxContent`), table column-header context inheritance. |
| **Org Pack PPTX** | 9 slides, native shapes, org charts, speaker notes, hidden slides | Recursive group shape extraction, hidden slide detection (`<p:sld show="0">`), speaker notes covert channel. |

---

## Getting Started

### 1. Environment Setup

Create and activate the project virtual environment:

```powershell
# Create virtual environment
python -m venv .venv

# Activate in PowerShell (Windows)
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

### 2. Run Automated Test Suite (409 Tests Passing)

Run the entire automated test suite (409 tests covering unit, adversarial evasion & corruption, multimodal integration, security checkpoint, and fail-closed gates):

```bash
# Full test suite (macOS/Linux)
pytest tests/ -q

# Windows PowerShell
.\.venv\Scripts\python.exe -m pytest tests/ -q
```

Run specialized test suites:

```bash
# Adversarial attack & evasion testing (corrupt files, evasion, leak injection)
pytest tests/adversarial/ -v

# Multimodal integration & security checkpoint tests
pytest tests/integration/ -v
```

### 3. Launch the Interactive Streamlit Security Gateway UI

Launch the enterprise security checkpoint dashboard:

```bash
streamlit run app.py
```

Features included in the dashboard:
- Single-document upload and batch audit inspector
- Interactive visual redaction diff viewer (text & burned bounding boxes)
- Inherent vs. Residual risk breakdown & critical dominance alert cards
- Zero-PII compliance audit log export & tamper-evident verification
- Fail-closed security checkpoint gate override and telemetry

### 4. Run Benchmark, Ablation, and LLM Utility Scripts

```bash
# 1. Generate multi-modal synthetic and held-out evaluation datasets
python scripts/generate_synthetic_datasets.py

# 2. Run empirical ablation study (Baseline Regex vs. Context-Enhanced 5-layer pipeline)
python src/evaluation/ablation.py

# 3. Run automated benchmark harness across raw, synthetic, and held-out datasets
python src/evaluation/benchmark.py

# 4. Reconstruct and sanitize Cadence benchmark documents (DOCX, PPTX, scanned PDF)
python scripts/reconstruct_cadence_artifacts.py

# 5. Run downstream 20-question LLM utility and zero-leak evaluation
python scripts/evaluate_llm_utility.py

# 6. Run interactive smoke test
python scripts/smoke_test.py
```

---

## Repository Structure

```
optiv/
├── app.py                      # Streamlit Security Gateway UI (Person 5)
├── README.md                   # System overview & setup instructions
├── requirements.txt            # Python dependencies
├── pytest.ini                  # Pytest discovery and pythonpath configuration
├── config/
│   └── policy.yaml             # Risk levels, actions, allow-lists (Person 4)
├── docs/
│   ├── architecture.md         # Master system architecture & data flow
│   ├── threat_model.md         # Threat model, security boundaries & policy guide
│   ├── evaluation.md           # Scientific evaluation & empirical benchmark report
│   ├── TEAM_INTEGRATION_GUIDE.md # Shared inter-developer integration contracts
│   ├── PROJECT_CHECKLIST.md    # Master 3-week project progress checklist (100% Complete)
│   ├── developer_1_ingestion_architecture.md
│   ├── developer_2_ocr_vision_architecture.md
│   ├── developer_3_pii_detection_architecture.md
│   ├── developer_4_policy_verifier_architecture.md
│   └── developer_5_evaluation_ui_architecture.md
├── scripts/
│   ├── smoke_test.py           # Interactive test runner & demonstration
│   ├── test_cadence_artifacts.py # Ingestion test on raw Cadence documents
│   ├── generate_synthetic_datasets.py # Multi-modal synthetic and held-out data generator
│   ├── reconstruct_cadence_artifacts.py # Sanitized document generator with pixel burning
│   └── evaluate_llm_utility.py # 20-question downstream LLM utility evaluation
├── src/
│   ├── ingestion/              # Ingestion & Parsers [Person 1]
│   │   ├── validators.py       # Pre-flight format & magic byte safety
│   │   ├── dispatcher.py       # Multi-format router & batch processor
│   │   ├── pdf.py              # PDF native reader & 220-DPI scanned renderer
│   │   ├── docx.py             # DOCX parser (tables, text boxes, images)
│   │   ├── pptx.py             # PPTX parser (shapes, notes, hidden slides)
│   │   └── metadata.py         # Metadata extraction & sanitization
│   ├── ocr/                    # Vision & OCR Pipelines [Person 2]
│   │   ├── engine.py           # EasyOCR & PaddleOCR adapter
│   │   ├── preprocess.py       # 220-DPI binarization & image enhancement
│   │   └── regions.py          # Coordinate transformations & bounding boxes
│   ├── schema/                 # Canonical Document Object Models [Person 1 Lead]
│   │   ├── document.py         # CanonicalDocument, ExtractedPage, EntityAnnotation
│   │   └── entities.py         # PII taxonomy, risk levels, and block models
│   ├── detection/              # PII Detection Stack [Person 3]
│   │   ├── regex.py            # Layer 1: High-precision deterministic patterns
│   │   ├── ner.py              # Layer 2: Presidio & spaCy local NER
│   │   ├── context.py          # Layer 3: Sliding cue windows & table context
│   │   ├── validators.py       # Layer 4: Checksum validators (Luhn, Verhoeff, E.164)
│   │   ├── resolver.py         # Layer 5: Overlap merging & conflict resolution
│   │   └── pipeline.py         # Orchestrated 5-layer detection pipeline
│   ├── policy/                 # Risk Model & Policy Engine [Person 4]
│   │   ├── policy.py           # Policy rules, actions & allow-lists
│   │   ├── risk.py             # Critical entity dominance risk model
│   │   └── relational.py       # Relational privacy & subject-predicate-object triples
│   ├── sanitization/           # Document Redaction & Reconstruction [Person 1, 2, 4]
│   │   ├── text_redactor.py    # Native text substitution & pseudonymization
│   │   ├── image_redactor.py   # True pixel burning with padding
│   │   ├── pdf_redactor.py     # Scanned & native PDF redaction
│   │   ├── docx_reconstructor.py # Native Word text replacement & image swapper
│   │   └── pptx_reconstructor.py # PowerPoint shape & speaker notes redactor
│   ├── security/               # Security Guardrails [Person 1 & 4]
│   │   ├── limits.py           # Zip bomb guard, XXE entity check, size caps
│   │   ├── input_safety.py     # Prompt injection isolation & Unicode defense
│   │   └── integrity.py        # Post-redaction document integrity verifier
│   ├── verification/           # Independent Verification & Gate [Person 4]
│   │   ├── verifier.py         # Heterogeneous secondary detector stack
│   │   ├── residual_scan.py    # Re-OCR scan on sanitized outputs
│   │   ├── gate.py             # Fail-closed AI Readiness gate
│   │   └── output_scanner.py   # Downstream LLM output interceptor
│   ├── audit/                  # Zero-PII Audit Logger [Person 4]
│   │   └── logger.py           # Salted-hash, zero-PII audit logging
│   └── evaluation/             # Metrics & Ablation Harness [Person 5]
│       ├── matcher.py          # Bounding-box IoU & text span matching
│       ├── metrics.py          # Recall, Precision, F1, Leak Rate, Over-Redaction
│       ├── benchmark.py        # Automated benchmark test harness
│       └── ablation.py         # Empirical ablation study (Baseline vs. Enhanced)
├── tests/
│   ├── unit/                   # 370 unit tests across all components
│   ├── adversarial/            # 15 tests: evasion, corrupt files, leak injection
│   └── integration/            # 24 integration tests: end-to-end & multimodal
└── data/
    ├── raw/                    # 3 Cadence enterprise benchmark artifacts
    ├── synthetic/              # Generated multi-modal test files
    ├── heldout/                # Frozen held-out evaluation test files
    ├── ground_truth/           # Frozen ground-truth JSON annotations
    └── outputs/                # Sanitized documents, OCR cache & audit logs
```

---

## 5-Person Team Structure

| Person | Role | Deliverables |
|---|---|---|
| **1** | **Lead Architect** | Canonical schema, pre-flight safety, multimodal extraction (PDF, DOCX, PPTX), reconstructors, and integrity guards. |
| **2** | **OCR & Vision Lead** | PaddleOCR/EasyOCR adapters, 220-DPI binarization, bounding boxes, true pixel burning redactor. |
| **3** | **PII Detection Lead** | Deterministic regex, Presidio + spaCy NER, sliding-window context, table header inheritance, checksum validators. |
| **4** | **Security Policy & Verifier** | Policy engine (`policy.yaml`), critical dominance risk model, independent secondary verifier, fail-closed gate. |
| **5** | **Evaluation & UI Lead** | Ground-truth benchmark, synthetic dataset generator, ablation runner, and Streamlit security dashboard. |
