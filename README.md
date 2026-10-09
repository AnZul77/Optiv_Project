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

### 2. Run Automated Unit Tests

Run the full pytest suite (19 unit tests covering ingestion, security limits, input safety, document reconstruction, and integrity guards):

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/ -v
```

### 3. Run Interactive Smoke Test & Demo

Run the end-to-end interactive demonstration:

```powershell
.\.venv\Scripts\python.exe scripts/smoke_test.py
```

### 4. Benchmark Ingestion on Cadence Artifacts

Run the multi-format ingestion test on the actual benchmark files:

```powershell
.\.venv\Scripts\python.exe scripts/test_cadence_artifacts.py
```

---

## Repository Structure

```
optiv/
├── app.py                      # Streamlit Security Gateway UI (Person 5)
├── README.md                   # System overview & setup instructions
├── requirements.txt            # Python dependencies
├── config/
│   └── policy.yaml             # Risk levels, actions, allow-lists (Person 4)
├── docs/
│   ├── architecture.md         # Master system architecture & data flow
│   ├── TEAM_INTEGRATION_GUIDE.md # Shared inter-developer integration contracts
│   ├── PROJECT_CHECKLIST.md    # Master 3-week project progress checklist
│   ├── developer_1_ingestion_architecture.md
│   ├── developer_2_ocr_vision_architecture.md
│   ├── developer_3_pii_detection_architecture.md
│   ├── developer_4_policy_verifier_architecture.md
│   └── developer_5_evaluation_ui_architecture.md
├── scripts/
│   ├── smoke_test.py           # Interactive test runner & demonstration
│   └── test_cadence_artifacts.py # Benchmark test on actual Cadence documents
├── src/
│   ├── ingestion/              # Ingestion & Parsers [Person 1]
│   │   ├── validators.py       # Pre-flight format & magic byte safety
│   │   ├── dispatcher.py       # Multi-format router & batch processor
│   │   ├── pdf.py              # PDF native reader & 220-DPI scanned renderer
│   │   ├── docx.py             # DOCX parser (tables, text boxes, images)
│   │   ├── pptx.py             # PPTX parser (shapes, notes, hidden slides)
│   │   └── metadata.py         # Metadata extraction & sanitization
│   ├── ocr/                    # Vision & OCR Pipelines [Person 2]
│   ├── schema/                 # Canonical Document Object Models [Person 1 Lead]
│   │   └── document.py         # CanonicalDocument, ExtractedPage, EntityAnnotation
│   ├── detection/              # PII Detection Stack [Person 3]
│   ├── policy/                 # Risk Model & Policy Engine [Person 4]
│   ├── sanitization/           # Document Redaction & Reconstruction [Person 1, 2, 4]
│   │   └── docx_reconstructor.py # Native Word text replacement & image swapper
│   ├── security/               # Security Guardrails [Person 1 & 4]
│   │   ├── limits.py           # Zip bomb guard, XXE entity check, size caps
│   │   ├── input_safety.py     # Prompt injection isolation & Unicode defense
│   │   └── integrity.py        # Post-redaction document integrity verifier
│   ├── verification/           # Independent Verification & Gate [Person 4]
│   ├── audit/                  # Zero-PII Audit Logger [Person 4]
│   └── evaluation/             # Metrics & Ablation Harness [Person 5]
└── tests/
    └── unit/                   # Unit test suite
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
