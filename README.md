# PII Security Firewall (Optiv Case Study)

**An OCR-First, Multimodal, Fail-Closed AI Security Gateway for Enterprise Ingestion**

The **PII Security Firewall** is an enterprise AI Security Gateway engineered to prevent Personally Identifiable Information (PII) from reaching downstream Large Language Models (LLMs). Operating inline between enterprise document repositories and AI systems, it ingests, extracts, detects, sanitizes, independently verifies, and strictly controls document flow.

If any detection confidence is low, extraction encounters an error, or post-redaction verification detects residual signals, the document is **BLOCKED**.

---

## Architecture Overview

```
User Uploads File (PDF, DOCX, PPTX, Images, TXT)
        │
        ▼
[1] Pre-Flight Security & Validation (Size limits, MIME, Magic Bytes, Zip Bomb Safety)
        │
        ▼
[2] Multimodal Extraction (Native text, 220-DPI OCR Rendering, Screenshots, Tables, Shapes, Metadata)
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

- **OCR-First Architecture**: OCR is not a fallback. Every page is treated as potentially containing visual PII (scanned forms, stamps, screenshots, org charts).
- **Defense in Depth**: Detection couples 5 independent layers: Deterministic Regex + Local Presidio/spaCy NER + Contextual Cue Windows + Algorithmic Validators (Luhn, Verhoeff, libphonenumbers) + Entity Resolution.
- **Independent Verification**: The verifier runs an independent, heterogeneous secondary detection stack. A detector's blind spot is never verified by its own logic.
- **Fail-Closed Security Gate**: If confidence is low ($\le 0.60$), extraction encounters an error, or verification is uncertain $\rightarrow$ **BLOCK**. Unknown is unsafe.
- **Irreversible Pixel Burning**: Redactions on scanned PDFs and images permanently burn solid opaque black pixels (`[0, 0, 0]`) into the image raster layer. No hidden visual text layers remain.
- **Zero-PII Audit Trail**: Logs record entity types, coordinates, actions, and salted SHA-256 hashes (`value_hash`). Raw PII is **never** written to disk or logs.
- **Downstream Response Firewall**: A second security boundary scans downstream LLM responses to prevent hallucinations or echoes from leaking PII to users.

---

## Supported File Formats & Artifact Challenges

| Format / Artifact | Structural Characteristics | Pipeline Handling & Redaction Strategy |
|---|---|---|
| **Scanned PDF** (`.pdf`) | 35-page scanned PDF (220-DPI JPEG pages, zero native text layer) | High-resolution 220-DPI page rendering; EasyOCR harvesting; sub-pixel coordinate alignment; figure PII extraction; irreversible pixel burning (`pdf_redactor.py`). |
| **Native / Hybrid PDF** (`.pdf`) | Multi-page digital text layer + embedded vector graphics | PyMuPDF redaction annotation burning with solid black fills + embedded image OCR inspection. |
| **Word Document** (`.docx`) | ~82 pages, ~38 embedded OneTrust screenshots, 16 tables, 4 text boxes | OpenXML text replacement in paragraphs, tables, text boxes (`w:txbxContent`) + embedded screenshot OCR & pixel burning. |
| **PowerPoint Deck** (`.pptx`) | Native shapes, org charts, speaker notes, hidden slides | Recursive OpenXML shape text replacement across all slides, tables, and speaker note covert channels. |
| **Images** (`.png`, `.jpg`, `.jpeg`, `.bmp`) | ID cards, badges, receipts, screenshots | EasyOCR text detection + bounding box calculation + true pixel burning (`image_redactor.py`). |
| **Plain Text** (`.txt`, `.log`, `.csv`) | Unstructured narrative text, server logs, prompt payloads | High-speed multi-layer regex + NER + context replacement with `[REDACTED_<TYPE>]` tokens. |

---

## Quick Start: Running with Docker (Recommended)

The gateway is fully containerized with Python 3.11, PyTorch CPU, EasyOCR with pre-cached models, spaCy, Tesseract OCR, Poppler, and Streamlit.

### 1. Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows / macOS / Linux)
- Ensure Docker daemon is running.

### 2. Launch with Docker Compose
From the project root directory, run:

```bash
docker compose up --build
```

Docker will build the container, pre-cache OCR weights, download the spaCy NLP model, and start the Streamlit Gateway on port **8501**.

### 3. Access the Gateway UI
Open your browser and navigate to:
```
http://localhost:8501
```

### 4. Stop the Container
To stop the gateway:
```bash
docker compose down
```

### Alternative: Direct Docker CLI
If you prefer building and running directly with the Docker CLI:

```bash
# Build the image
docker build -t pii-security-firewall .

# Run the container (mounting the outputs directory)
docker run -d -p 8501:8501 --name pii-firewall \
  -v "$(pwd)/data/outputs:/app/data/outputs" \
  pii-security-firewall
```

---

## Running Locally (Development Mode)

### 1. Prerequisites
- Python 3.10 or 3.11
- Git

### 2. Setup Virtual Environment

**On Windows (PowerShell):**
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install dependencies
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# Download spaCy English model
python -m spacy download en_core_web_sm
```

**On macOS / Linux (Bash):**
```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# Download spaCy English model
python -m spacy download en_core_web_sm
```

### 3. Launch the Streamlit Gateway UI
```bash
streamlit run app.py
```
Open your browser to `http://localhost:8501`.

---

## Using the Security Gateway UI

1. **Upload Any Document**: Drag and drop any `.pdf`, `.docx`, `.pptx`, `.png`, `.jpg`, or `.txt` file into the upload zone.
2. **Automated Pipeline Execution**: The gateway automatically executes all 5 stages:
   - **Stage 1 (Ingestion)**: Validates MIME/magic bytes, decompresses safely, extracts text, tables, and images.
   - **Stage 2 (5-Layer Detection)**: Identifies PII across Regex, Presidio/spaCy NER, Context Cues, Checksum Validators, and Span Resolution.
   - **Stage 3 (Policy Engine)**: Applies corporate risk policies and allow-lists (`policy.yaml`).
   - **Stage 4 (Sanitization & Reconstruction)**: Performs irreversible pixel burning on images/PDFs and native text replacement in Office documents.
   - **Stage 5 (Fail-Closed Gate)**: Evaluates independent secondary verification and residual scans (`AI READY: PASS` or `AI READY: BLOCK`).
3. **Interactive Side-by-Side Preview**:
   - **PDFs**: Page selector to view the original high-resolution page side-by-side with the pixel-burned sanitized page.
   - **Images**: Original image side-by-side with the pixel-burned sanitized image.
   - **DOCX / PPTX / TXT**: Original text stream (with color-coded PII highlights) side-by-side with the sanitized egress stream.
4. **Download Sanitized Artifact**: Click **📥 Download Sanitized Document** to export the ready-to-use redacted file.
5. **Download Cryptographic Audit Trail**: Click **📋 Download Session Audit Log** to export the salted SHA-256 audit record.
6. **Test Downstream LLM Response Firewall**: Use the built-in Second Security Boundary simulator to test how the gateway intercepts hallucinated PII in LLM output streams.

---

## Automated Test Suite (688 Tests Passing)

The project includes an exhaustive automated test suite covering unit tests, multimodal artifacts, OCR alignment, policy enforcement, adversarial evasion, and prompt injection vectors.

Run all tests:
```bash
pytest tests/ -v
```

Run specific test modules:
```bash
# Ingestion and format validation
pytest tests/unit/test_ingestion.py -v

# OCR coordinate precision and figure pixel burning
pytest tests/unit/test_cadence_pdf_regions_precision.py -v

# Policy engine and allow-lists
pytest tests/unit/test_policy.py -v

# Fail-closed AI readiness gate
pytest tests/unit/test_gate.py -v

# Adversarial evasion & prompt injection attack suite
pytest tests/adversarial/ -v

# 20-Question Cadence LLM Utility Evaluation
pytest tests/integration/test_llm_utility.py -v
```

---

## Key Scripts & Utilities

### 1. Reconstruct Cadence Artifacts
To execute batch reconstruction and pixel-level burning across the 3 benchmark Cadence artifacts (Scanned PDF, TPRM DOCX, and Org Pack PPTX):
```bash
python scripts/reconstruct_cadence_artifacts.py
```
Output sanitized files will be written to `data/outputs/`.

### 2. Residual OCR Leak Scanner
To scan a sanitized PDF page-by-page using EasyOCR to verify 0 residual PII leaks remain:
```bash
python scripts/scan_sanitized_pdf_leaks.py
```

### 3. Run Context vs. Baseline Ablation Experiment
```bash
python -m src.evaluation.ablation
```
Results and precision/recall comparisons are exported to `reports/evaluation/ablation_results.md`.

---

## Project Directory Layout

```
optiv/
├── app.py                      # Streamlit Security Gateway UI
├── Dockerfile                  # Production container definition (Python 3.11, OCR, Torch)
├── docker-compose.yml          # Container orchestration & volume mapping
├── requirements.txt            # Production Python dependencies
├── README.md                   # System documentation & execution guide
├── config/
│   └── policy.yaml             # Risk thresholds, actions, allow-lists
├── src/
│   ├── ingestion/              # [Person 1] Format validation & extraction
│   │   ├── validators.py       # Magic bytes, MIME, zip bomb guards
│   │   ├── dispatcher.py       # Multi-format router (PDF, DOCX, PPTX, Image, TXT)
│   │   ├── pdf.py              # PDF native & scanned page reader
│   │   ├── docx.py             # DOCX parser (tables, text boxes, images)
│   │   ├── pptx.py             # PPTX parser (shapes, notes, hidden slides)
│   │   └── metadata.py         # Metadata extraction & property scrubbing
│   ├── ocr/                    # [Person 2] OCR engine & coordinate bounding
│   │   ├── engine.py           # EasyOCR engine adapter
│   │   ├── regions.py          # Bounding-box coordinate generator
│   │   ├── cadence_figures.py  # Precision bounding boxes for complex document figures
│   │   └── confidence.py       # Character & word confidence scoring
│   ├── schema/                 # Canonical schemas (CanonicalDocument, EntityAnnotation)
│   ├── detection/              # [Person 3] 5-Layer PII detection pipeline
│   │   ├── regex.py            # High-precision deterministic regex catalog
│   │   ├── ner.py              # Presidio + spaCy NER engine
│   │   ├── context.py          # Sliding cue window & table header inheritance
│   │   ├── validators.py       # Luhn, Verhoeff, libphonenumbers checksums
│   │   └── resolver.py         # Span deduplication & conflict resolver
│   ├── policy/                 # [Person 4] Policy engine & risk scoring
│   │   ├── policy.py           # YAML policy rules & allow-lists
│   │   └── risk.py             # Inherent vs. residual risk scoring
│   ├── sanitization/           # [Person 1, 2, 4] Redaction & document reconstruction
│   │   ├── text_redactor.py    # Native text replacement
│   │   ├── image_redactor.py   # True pixel burning on raster images
│   │   ├── pdf_redactor.py     # Burned pixel redactions on scanned PDFs
│   │   ├── docx_reconstructor.py # Word document reconstruction & image replacement
│   │   └── pptx_reconstructor.py # PowerPoint shape & note reconstruction
│   ├── verification/           # [Person 4] Independent secondary verification
│   │   ├── verifier.py         # Heterogeneous secondary detector stack
│   │   ├── residual_scan.py    # Re-OCR residual scan engine
│   │   ├── output_scanner.py   # Downstream LLM Response Firewall
│   │   └── gate.py             # Fail-closed AI Readiness Gate
│   ├── audit/                  # [Person 4] Zero-PII cryptographic audit logger
│   └── evaluation/             # [Person 5] Benchmark harness & ablation
├── data/
│   ├── raw/                    # Original input artifacts
│   ├── ground_truth/           # Frozen ground-truth entity annotations
│   └── outputs/                # Sanitized documents, OCR cache, audit trails
├── docs/                       # Technical architecture & threat model docs
└── tests/                      # Automated test suite (688 unit & integration tests)
```

---

## License & Security Compliance

Developed for enterprise AI document security and regulatory privacy compliance (GDPR, HIPAA, CCPA, PCI-DSS). All redactions perform true irreversible data removal. Plaintext PII is never persisted.
