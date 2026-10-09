# AGENTS.md: PII Security Firewall (Optiv Case Study)

## Project Overview
**PII Security Firewall** — a local/approved-environment AI Security Gateway that prevents Personally Identifiable Information (PII) from reaching downstream LLM systems. Uses a fail-closed, OCR-first, multimodal architecture. If confidence is low or verification is uncertain, the document is **BLOCKed**.

**Primary Goal**: Detect, sanitize, independently verify, and strictly control document flow so no PII leaks to approved LLWs.

**Duration**: 3-week (21-day) implementation — this repo is currently a skeleton; see the 3-week roadmap below.

---

## Architecture Diagram (from PRD)

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
Risk & Policy Engine ────[BLOCK]────► Disallowed / Alert
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

---

## Core Security Philosophy (from PRD)

- **OCR-First**: OCR is not a fallback. Every page is treated as potentially containing visual PII (scanned forms, stamps, screenshots, org charts).
- **Defense in Depth**: No single detector is trusted. Detection couples Regex + NER + Context Rules + Document Structure + Algorithmic Validators.
- **Independent Verification**: The verifier runs a **different** detection stack than the primary detector. A detector's blind spot should not be repeated by its own verifier.
- **Fail Closed**: If confidence is low, extraction fails, or verification is uncertain → **BLOCK**. Unknown is unsafe.
- **Redaction by Default**: Inherent PII is redacted. Pseudonymization mappings are secondary to the 3-week MVP.

---

## Supported Inputs & Artifact Challenges

| Artifact | Structure Characteristics | Key Challenge & Focus |
|---|---|---|
| **Risk Policy PDF** | 35-page scanned PDF, 220-dpi JPEG pages, zero native text layer | Must OCR every page. Page 22 has dense narrative prose PII (names, SSN, DOB, passports, PAN, home address). |
| **TPRM Training DOCX** | ~82 pages, ~38 embedded OneTrust screenshots, 16 tables, 4 text boxes | Embedded screenshot extraction, OCR on images, table header context resolution. |
| **Org Pack PPTX** | 9 slides, native shapes, org charts, speaker notes, hidden slides | Small text inside diagrams, visual organization hierarchy, hidden channels/notes. |

---

## PII Taxonomy & Detection Architecture

### PII Types (from PRD)

- **Identity**: `PERSON`, `DOB`, `ADDRESS`
- **Contact**: `EMAIL`, `PHONE`
- **Organization IDs**: `EMPLOYEE_ID`, `DIRECTOR_ID`
- **National / Govt IDs**: `SSN`, `PASSPORT`, `PAN`, `TAX_ID`, `AADHAAR`, `NINO`
- **Financial**: `CARD`, `BANK_ACCOUNT`, `IFSC`, `GST`, `UPI`
- **Visual Signals**: `SIGNATURE`, `FACE/PHOTO`, `SENSITIVE_SCREENSHOT`
- **Allow-list (False-Positive Prevention)**: `INC-\d{4}-\d+`, `RSK-\d+`, `GRP-POL-\d+`, `CTL-IAM-\d+`

### 5 Detection Layers (from PRD)

1. **Layer 1: Regex Engine** — Deterministic patterns for email, phone, SSN, PAN, Aadhaar, cards, employee IDs.
2. **Layer 2: Local NER Engine** — Presidio + spaCy NER for unstructured narrative names, locations, organizations.
3. **Layer 3: Context Engine** — Sliding window token cues (`"SSN:"`), table header inheritance (`Emp ID` → cell values), document-level section triggers (`"Employee Personal Information"`).
4. **Layer 4: Validators** — Algorithmic checks (Luhn, Verhoeff, libphonenumbers) modify confidence without discarding non-standard synthetic data.
5. **Layer 5: Entity Resolver** — Overlapping span merging and conflict resolution into a unified schema.

### Entity JSON Schema (from PRD)

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

## 5-Person Team Structure (from PRD)

| Person | Role | Key Directories |
|---|---|---|
| **1** | Lead Architect | Ingestion, Dispatcher & Multimodal Extraction — `src/ingestion/`, `src/schema/document.py` |
| **2** | OCR & Vision Lead | OCR Pipelines, Bounding Boxes & Pixel Redactor — `src/ocr/`, `src/sanitization/` |
| **3** | PII Detection Lead | Regex, Spacy/Presidio NER, Context & Entity Resolution — `src/detection/`, `src/schema/entities.py` |
| **4** | Security Policy & Verifier | Policy Engine, Secondary Verifier, Audit Log & Fail-Closed Gate — `src/policy/`, `src/verification/`, `src/audit/` |
| **5** | Evaluation, Benchmark & UI | Synthetic/Adversarial Datasets, Benchmark Metrics & Streamlit — `src/evaluation/`, `app.py`, `tests/` |

---

## Repository Directory Layout (from PRD Section 7)

```
pii-security-firewall/
├ app.py                      # Streamlit Security Gateway UI
├ README.md                   # Setup, architecture & run instructions
├ requirements.txt            # Python dependencies (presidio, spacy, easyocr/paddleocr, etc.)
├ Dockerfile                  # Local containerized gateway build
├ config/
│   └── policy.yaml           # Risk levels, actions, allow-lists
├ src/
│   ├── ingestion/            # [Person 1]
│   │   ├── validators.py     # File format & size safety
│   │   ├── dispatcher.py     # Multi-format router
│   │   ├── pdf.py            # PDF native & scanned page reader
│   │   ├── docx.py           # DOCX parser (tables, text boxes, images)
│   │   ├── pptx.py           # PPTX parser (shapes, notes, hidden slides)
│   │   └── metadata.py       # Metadata & hidden content extractor
│   ├── ocr/                  # [Person 2]
│   │   ├── engine.py           # OCR engine adapter (PaddleOCR / EasyOCR)
│   │   ├── preprocess.py       # Image binarization & upscaling
│   │   ├── regions.py          # Bounding-box coordinate generator
│   │   └── confidence.py       # Character & word confidence scoring
│   ├── schema/               # [All / P1 Lead]
│   │   ├── document.py         # Canonical document object models
│   │   └── entities.py         # PII entity schema & audit models
│   ├── detection/            # [Person 3]
│   │   ├── regex.py            # High-precision deterministic patterns
│   │   ├── ner.py              # Local Presidio + spaCy NER
│   │   ├── context.py          # Sliding cue window & table header context
│   │   ├── validators.py       # Luhn, Verhoeff & format checksums
│   │   └── resolver.py         # Span deduplication & conflict resolver
│   ├── policy/               # [Person 4]
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
├ data/
│   ├── raw/                  # 3 supplied Cadence documents
│   ├── synthetic/              # Generated test documents
│   ├── ground_truth/           # Frozen ground-truth annotations
│   ├── heldout/                # Never-tuned test set
│   └── outputs/                # Sanitized documents & audit trails
├ tests/
│   ├── unit/                   # Component tests
│   ├── integration/            # Pipeline tests
│   ├── adversarial/            # Evasion attack tests
│   └── regression/             # CI regression checks
├ reports/
│   ├── evaluation/             # Benchmark metrics & ablation tables
│   ├── figures/                # Visual comparison charts
│   └── logs/                   # Execution logs
└ docs/
    ├── architecture.md         # System design & data flow
    ├── threat_model.md         # Threat actors & mitigations
    └── evaluation.md           # Empirical benchmark results
```

---

## 3-Week Implementation Roadmap (from PRD)

```
WEEK 1: Architecture, Extraction, Freezing & Core Detection
Day 1: Environment, Sample Inspection, Common Schema & Base Architecture
Day 2: PDF Extraction & OCR Benchmarking
Day 3: DOCX Extraction (38 screenshots & tables) & Regex Catalog
Day 4: PPTX Extraction & NER Integration
Day 5: FREEZE EXTRACTOR CHECKPOINT & Ground Truth Annotation Start
Day 6: Context Engine & Checksum Validators
Day 7: Week 1 Integration Review & Entity Resolver Benchmark

WEEK 2: Security Pipeline, Redaction & Independent Verification
Day 8: Policy Engine & Inherent Risk Model (config/policy.yaml)
Day 9: Text Redaction Engine & Native Document Reconstruction
Day 10: Image Pixel Masking & PDF/DOCX Image Replacement
Day 11: Re-OCR Engine for Sanitized Artifacts
Day 12: Independent Verifier Engine (Secondary Stack)
Day 13: Fail-Closed Gate & Zero-PII Audit Logger
Day 14: Week 2 Integration Review & End-to-End Pipeline Smoke Test

WEEK 3: Evaluation, Adversarial Suite, UI & Final Delivery
Day 15: Synthetic Dataset Generation & Frozen Held-Out Test Splits
Day 16: Benchmark Execution (Baseline vs. Context-Enhanced Ablation)
Day 17: Adversarial Attack Suite & Evasion Testing
Day 18: LLM Utility Evaluation (20 Q&A consistency & degradation tests)
Day 19: Streamlit Security Checkpoint Dashboard
Day 20: Full End-to-End Testing on 3 Cadence Artifacts
Day 21: Documentation, Threat Model, Architecture Diagrams & Final Demo
```

---

## Key Commands & Conventions

| Action | Command / Note |
|---|---|
| **Install dependencies** | `pip install -r requirements.txt` (when present) |
| **Run the Streamlit UI** | `streamlit run app.py` (when implemented) |
| **Docker build** | `docker build -t pii-firewall .` (when Dockerfile is filled in) |
| **Python environment** | Use a virtual environment; `requirements.txt` lists presiodelabs/spaCy/easyocr/paddleocr |
| **Fail-closed behavior** | If any detector/verifier returns uncertain/low confidence → BLOCK. No PII should ever silently pass. |

---

## What to Do First (agent onboarding)

1. **Populate the skeleton** — replace `.gitkeep` files with actual code per the PRD `src/` layout.
2. **Fill `config/policy.yaml`** — define REDACT/BLOCK/ALLOW rules and allow-lists (`INC-*`, `RSK-*`, etc.).
3. **Implement ingestion** — start with `src/ingestion/pdf.py` and `src/ingestion/docx.py` per the Day 2–3 roadmap.
4. **Add OCR pipeline** — `src/ocr/engine.py` with PaddleOCR/EasyOCR benchmarking (Day 2).
5. **Build the detection stack** — regex → NER → context → validators → resolver (Days 4–6).
6. **Freeze extractor checkpoint** — lock `CanonicalDocument` schema and OCR coordinates before annotation (Day 5).
7. **Implement fail-closed gate** — `src/verification/gate.py` with independent verifier and audit logger (Days 12–13).
8. **Run the 3-cadence-artifact smoke test** — Risk Policy PDF, TPRM DOCX, Org Pack PPTX (Day 14 / Day 20).
9. **Generate evaluation metrics** — Recall, Precision, F1, Document Leak Rate, Over-Redaction Rate (Week 3).
10. **Update `README.md` and `docs/`** — architecture, threat model, and evaluation writeups (Day 21).

---

## What NOT to Do

- ❌ Do **not** assume any detector is 100% accurate. The system is fail-closed by design.
- ❌ Do **not** let the primary detector's blind spot be repeated by the verifier — the verifier must use a **different** stack.
- ❌ Do **not** allow low-confidence PII to pass through. Fail closed: block if uncertain.
- ❌ Do **not** redact visual PII (signatures, faces, screenshots) only via text matching — use OCR + pixel burning (`src/sanitization/image_redactor.py`).
- ❌ Do **not** skip the independent verification step (Person 4's verifier) before marking any document AI_READY.

---

## References Within This Repo

- **PRD**: `pii-security-firewall/docs/PRD_IMPLEMENTATION_PLAN.md` — full product requirements
- **Roadmap**: Sections 5 (Weeks 1–3) and 6 (Performance Metrics) in the PRD
- **Team structure**: Section 4 (5-Person Team) in the PRD
- **Directory layout**: Section 7 in the PRD
- **Team conventions**: Person profiles in the PRD (modules, deliverables, key files)