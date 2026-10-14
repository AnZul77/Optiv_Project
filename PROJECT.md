# Project: PII Security Firewall (Optiv Multi-Agent Overhaul)

## Architecture
- **Ingestion & Parsing (`src/ingestion/`)**: Multi-format router (`pdf.py`, `docx.py`, `pptx.py`, `metadata.py`) converting documents into canonical representations.
- **Vision & OCR Engine (`src/ocr/`)**: Scanned page rasterization, OCR region extraction, word-level bounding box calculations (`regions.py`), DPI scaling, and OCR cache management.
- **Multi-Layer Detection (`src/detection/`)**: 5-layer pipeline combining deterministic Regex (`regex.py`), Local NER with spaCy/Presidio (`ner.py`), Context sliding windows (`context.py`), Checksum/format Validators (`validators.py`), and Conflict-resolving Entity Resolver (`resolver.py`).
- **Policy Engine (`src/policy/`)**: Evaluates risk and applies REDACT/BLOCK/ALLOW actions with strict business allow-lists (`config/policy.yaml`).
- **Sanitization & Pixel Redactor (`src/sanitization/`)**: Native text redactor (`text_redactor.py`), true raster pixel burning (`image_redactor.py`), and scanned PDF reconstructor (`pdf_redactor.py`).
- **Independent Verification & Gate (`src/verification/`)**: Secondary heterogeneous detection stack (`verifier.py`), residual re-OCR page scanner (`residual_scan.py`), and fail-closed security gate (`gate.py`).
- **Gateway Dashboard (`app.py`)**: Streamlit user interface featuring live document upload, interactive before/after visual inspection, policy audit trails, and sanitized download.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Proportional Font Box Alignment | Replace linear character interpolation in `extract_word_level_pii_boxes` with token bounding boxes to eliminate leading/trailing cut-offs (e.g. `Pr [box]`) | M1 | R2 / Survey 1 & 2 |
| 2 | Middle-Initial & Phrase Bridging | Bridge first name, middle initial, and surname in `find_pii_spans_in_text` to eliminate 20px gaps over middle initials (`Devansh R. Kulkarni`, `Rohan S. Deshmukh`, `Rafael E: Duarte`) | M1 | R2 / Survey 2 & 3 |
| 3 | Standardized 5px Safety Margin | Enforce 5px padding margin across `pdf_redactor.py`, `image_redactor.py`, and `reconstruct_cadence_artifacts.py` | M1 | R2 / Survey 1 & 2 |
| 4 | OCR Character Error Variant Matching | Expand OCR error variant coverage in regex/phrase matching for OCR-degraded tokens (`Briqhtwell`, `Privanka`, `Emilic`, `Valdvanathan`) | M1 | R2 / Survey 2 |
| 5 | Synthetic SSN 900-Series Support | Remove `(?!9\d{2})` negative lookahead in `regex.py` to detect synthetic SSNs on Page 22 (`900-55-2043`, `900-42-7781`) | M2 | R1 / Survey 3 |
| 6 | Polish PESEL Detection | Add deterministic pattern for Polish PESEL (`890412xxxxx`) in `regex.py` and `regions.py` | M2 | R1 / Survey 3 |
| 7 | Partial Financial & Identity Tokens | Detect partial card ending `2218`, savings account ending `7741`, and SSN last 4 digits `(8827)` in `regex.py` and `regions.py` | M2 | R1 / Survey 3 |
| 8 | International Phone Formats & Country Code Preservation | Add Polish (`+48`), French (`+33 1`), and UK (`+44`) phone formats; prevent validator/resolver from stripping `+48` country codes | M2 | R1 / Survey 3 |
| 9 | Non-Anglo Personnel Name Coverage | Overcome spaCy misclassifications (`ORG`/`GPE`) for diverse executive names via roster gazetteer / composite patterns in `ner.py` and `regions.py` across all 34 PII-bearing pages | M2 | R1 / Survey 3 |
| 10 | Business Code Allow-List Preservation | Protect safe business context (`GRP-POL-001`, `RSK-*`, `CTL-IAM-*`, table headers) from false-positive over-redaction | M2 | R2 / Survey 1 & 3 |
| 11 | True Pixel Burning PDF Reconstruction | Reconstruct 35-page sanitized PDF (`data/outputs/sanitized_Cadence_Group_Risk_Management_Policy__v6.0.pdf`) with burned black boxes, 5px safety margin, and 0 corruption | M3 | Acceptance / Survey 1 & 2 |
| 12 | Punctuation Prefix Redaction Fix | Ensure leading quotation marks and punctuation (e.g. `'"Tobias Lindqvist'` on Page 34) do not shift or escape pixel burning | M3 | Survey 1 |
| 13 | Heterogeneous Secondary Verifier | Upgrade `src/verification/verifier.py` with rules for un-cued personal names, PESEL, partial tokens, French phones, and OCR variations | M4 | R3 / Survey 3 |
| 14 | Residual Re-OCR Verification | Run post-redaction re-OCR scan across all 35 pages of the sanitized PDF via `residual_scan.py` yielding 0 detected residual PII tokens | M4 | R3 / Survey 1 & 3 |
| 15 | Ground Truth Annotation Update | Update `data/ground_truth/cadence_risk_policy.json` to reflect verified entities across the 35-page document | M4 | Survey 1 |
| 16 | Streamlit Security Gateway UI | Verify and update `app.py` for live document upload, interactive before/after visual preview, and unblocked sanitized download | M5 | Acceptance / Survey 1 |
| 17 | Full Pytest Regression Suite | Run `.venv\Scripts\python -m pytest tests/` and ensure 100% pass rate (463+ tests) with 0 regressions | M5 | Acceptance / Survey 1 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Vision/OCR & Bounding Box Alignment | Features 1, 2, 3, 4: `src/ocr/regions.py`, `src/sanitization/pdf_redactor.py`, `src/sanitization/image_redactor.py` | None | DONE (630 passed, 0 regressions) |
| M2 | PII Detection & Entity Resolution | Features 5, 6, 7, 8, 9, 10: `src/detection/regex.py`, `ner.py`, `validators.py`, `resolver.py`, `src/ocr/regions.py` | None | IN_PROGRESS (16994117-3d1b-4160-b661-767e4e3e2346) |
| M3 | Pixel Burning & PDF Reconstruction | Features 11, 12: `scripts/reconstruct_cadence_artifacts.py`, `data/outputs/sanitized_Cadence_Group_Risk_Management_Policy__v6.0.pdf` | M1, M2 | PLANNED |
| M4 | Secondary Verifier & Re-OCR Residual Scan | Features 13, 14, 15: `src/verification/verifier.py`, `residual_scan.py`, `gate.py`, `data/ground_truth/cadence_risk_policy.json` | M3 | PLANNED |
| M5 | Streamlit UI & Full Test Regression | Features 16, 17: `app.py`, `pytest tests/`, E2E pipeline verification | M4 | PLANNED |

## Interface Contracts
### `src/ocr/regions.py` ↔ `src/sanitization/pdf_redactor.py`
- `extract_word_level_pii_boxes(ocr_results: list[dict], width: int, height: int, padding: int = 5) -> list[tuple[float, float, float, float]]`
- Coordinate output: Normalized `(x0, y0, x1, y1)` in `[0.0, 1.0]` with 5px safety margin applied at pixel raster scale.
- No characters cut off or truncated. Contiguous multi-word names with middle initials merged into continuous bounding boxes.

### `src/detection/regex.py` & `src/detection/ner.py` ↔ `src/detection/resolver.py`
- Standard `PIIEntity` schema with entity types: `PERSON`, `DOB`, `ADDRESS`, `EMAIL`, `PHONE`, `SSN`, `PASSPORT`, `PAN`, `PESEL`, `FINANCIAL_TOKEN`.
- Phone numbers: Full international format (e.g. `+48 512 555 0180`) preserved by validator and resolver.

### `src/verification/verifier.py` ↔ `src/verification/gate.py`
- Independent verifier operates on OCR text and sanitized artifacts with zero shared blind spots.
- Returns `VerificationResult(passed=bool, findings=list[Finding])`.
- Fail-closed gate: if `not result.passed` or residual PII found, `GATE_STATUS = BLOCKED`.

## Code Layout
```
c:\Users\anshu\Documents\codes\optiv\
├ app.py
├ config/policy.yaml
├ src/
│   ├ ingestion/ (validators.py, dispatcher.py, pdf.py, docx.py, pptx.py, metadata.py)
│   ├ ocr/ (engine.py, preprocess.py, regions.py, confidence.py)
│   ├ schema/ (document.py, entities.py)
│   ├ detection/ (regex.py, ner.py, context.py, validators.py, resolver.py)
│   ├ policy/ (risk.py, policy.py)
│   ├ sanitization/ (text_redactor.py, image_redactor.py, pdf_redactor.py)
│   ├ verification/ (verifier.py, residual_scan.py, gate.py)
│   └ audit/ (logger.py)
├ scripts/
│   ├ reconstruct_cadence_artifacts.py
│   └ update_highres_ocr_cache.py
├ data/
│   ├ raw/Cadence_Group_Risk_Management_Policy__v6.0.pdf
│   ├ outputs/ocr_cache_policy_v6.json
│   ├ outputs/sanitized_Cadence_Group_Risk_Management_Policy__v6.0.pdf
│   └ ground_truth/cadence_risk_policy.json
└ tests/
    ├ unit/
    ├ integration/
    └ adversarial/
```
