# Developer 3: PII Detection & Context Engine Architecture Guide

**Role:** Person 3 — PII Detection Lead  
**Domain:** Deterministic Regex, Local Presidio/spaCy NER, Contextual Reasoning, Checksum Validators, and Entity Resolution  
**Key Modules:** `src/detection/regex.py`, `src/detection/ner.py`, `src/detection/context.py`, `src/detection/validators.py`, `src/detection/resolver.py`, `src/schema/entities.py`  

---

## 1. Role Purpose & Core Security Mandate

Developer 3 is responsible for the **multi-layer semantic detection core** of the PII Security Firewall.

In this gateway:
1. **Defense in Depth**: No single detector is trusted. Detection couples **5 distinct layers**:
   - Layer 1: High-precision deterministic regular expressions.
   - Layer 2: Machine-learned Named Entity Recognition (NER) via Microsoft Presidio and local spaCy models.
   - Layer 3: Context cues (token windows, table column header inheritance, document section triggers).
   - Layer 4: Algorithmic checksum validators (Luhn, Verhoeff, libphonenumbers).
   - Layer 5: Overlapping span deduplication and conflict resolution.
2. **Context-Aware Disambiguation**: Raw tokens like `"987-65-4321"` or `"EMP-1029"` are ambiguous in isolation. Developer 3 leverages table column headers inherited from Developer 1 (`TableCell.header_name`) and surrounding prefix tokens (`"SSN:"`, `"Employee Tax ID:"`) to boost confidence.
3. **Strict Zero-PII Standard**: Developer 3 must emit canonical `EntityAnnotation` objects where the detected value is hashed via salted SHA-256 (`value_hash`). Plaintext PII must never be stored in detection entities or logs.

---

## 2. PII Taxonomy & Risk Classification

| PII Category | Entity Type | Detection Strategy | Baseline Risk |
|---|---|---|---|
| **National / Govt IDs** | `SSN`, `PASSPORT`, `PAN`, `AADHAAR`, `TAX_ID`, `NINO` | Regex + Checksum + Context | **CRITICAL** |
| **Financial Data** | `CARD`, `BANK_ACCOUNT`, `IFSC`, `GST`, `UPI` | Regex + Luhn + Context | **CRITICAL** |
| **Identity Data** | `PERSON`, `DOB`, `ADDRESS` | Presidio/spaCy NER + Context Window | **HIGH** |
| **Contact Data** | `EMAIL`, `PHONE` | Regex + libphonenumbers | **HIGH** |
| **Org / Enterprise IDs**| `EMPLOYEE_ID`, `DIRECTOR_ID` | Regex + Table Header Context | **MEDIUM** |
| **Allow-listed Codes** | `INC-\d{4}-\d+`, `RSK-\d+`, `GRP-POL-\d+` | Regex Exclusion (Allow-list) | **PASS / NONE** |

---

## 3. Directory & Module Specifications

```
src/
├── schema/
│   └── entities.py           # Taxonomy constants, risk weights, entity types
└── detection/
    ├── __init__.py           # Package exports
    ├── regex.py              # Layer 1: Deterministic regex catalog
    ├── ner.py                # Layer 2: Presidio + spaCy NER pipeline
    ├── context.py            # Layer 3: Sliding window cue & table header context injector
    ├── validators.py         # Layer 4: Luhn, Verhoeff, checksum algorithms
    └── resolver.py           # Layer 5: Overlapping span resolver & conflict deduplicator
```

---

## 4. Layer-by-Layer Technical Requirements

### 4.1 Layer 1: Regex Catalog (`src/detection/regex.py`)
- **Deterministic Patterns**:
  - `EMAIL`: RFC 5322-compliant expression.
  - `PHONE`: E.164 and North American Numbering Plan (`(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`).
  - `SSN`: Standard format `\b\d{3}-\d{2}-\d{4}\b` and digit-run variants.
  - `PAN` (India): `[A-Z]{5}[0-9]{4}[A-Z]`.
  - `AADHAAR` (India): `\b\d{4}\s\d{4}\s\d{4}\b`.
  - `CARD`: Credit card numbers (13–19 digits, with/without dashes).
  - `EMPLOYEE_ID`: Corporate prefixes like `EMP-\d{4,8}` or `ID:\s*\d{6}`.

### 4.2 Layer 2: Local NER Engine (`src/detection/ner.py`)
- **Offline / Local Execution**:
  - Run Microsoft Presidio (`presidio-analyzer`) configured with `en_core_web_sm` or `en_core_web_md` spaCy model.
  - Extract unstructured narrative names (`PERSON`), physical locations (`ADDRESS`), and organizations (`ORGANIZATION`).
  - Specially tune sensitivity for dense prose PII (e.g., Page 22 of the Risk Policy PDF).

### 4.3 Layer 3: Context Engine (`src/detection/context.py`)
- **Sliding Window Token Cues**:
  - Scan $k=5$ tokens preceding and following a candidate entity for contextual triggers (`"DOB:"`, `"Date of birth"`, `"Taxpayer"`, `"Social Security"`).
  - Adjust base confidence score by $+0.20$ to $+0.35$ when matching cues are present.
- **Table Column Header Inheritance**:
  - Consume Developer 1's `TableCell.header_name`.
  - If a cell text `"123-45-6789"` is in a column named `"SSN"`, upgrade confidence from $0.65$ to $0.99$ and mark risk as `CRITICAL`.
- **Document Section Triggers**:
  - Headings like `"Confidential Employee Roster"` or `"Third-Party Risk Assessment"` elevate base sensitivity.

### 4.4 Layer 4: Algorithmic Checksum Validators (`src/detection/validators.py`)
- **Luhn Algorithm**: Validate credit card numbers; flag invalid test cards vs. real cards.
- **Verhoeff Algorithm**: Validate 12-digit Indian Aadhaar numbers.
- **Phone Validator**: Validate phone numbers against international country plans via `phonenumbers` library.

### 4.5 Layer 5: Entity Resolver (`src/detection/resolver.py`)
- **Span Conflict Resolution**:
  - When Regex, NER, and Context engines detect overlapping character offsets (`[text_start, text_end]`):
    - Merge nested spans (e.g. `"John Smith"` inside `"Dr. John Smith, MD"`).
    - Favor higher-specificity types (`SSN` > `GENERIC_NUMBER`, `PERSON` > `ORG`).
    - Compute composite confidence:
      $$\text{Confidence} = 0.35 \cdot C_{\text{regex}} + 0.30 \cdot C_{\text{NER}} + 0.20 \cdot C_{\text{context}} + 0.15 \cdot C_{\text{validator}}$$
  - Emit unified `List[EntityAnnotation]` attached to `CanonicalDocument.entities`.

---

## 5. Integration Contracts with Other Developers

1. **From Developer 1**:
   - Consume `page.combined_text`, `page.blocks`, and `table.rows` with `TableCell.header_name`.
2. **From Developer 2**:
   - Consume `page.ocr_text` and word-level bounding boxes for visual text extracted from screenshots and scanned pages.
3. **To Developer 4 (Policy & Verification)**:
   - Provide populated `CanonicalDocument.entities` with `risk` (`CRITICAL`, `HIGH`, `MEDIUM`) and suggested `action` (`REDACT`, `BLOCK`, `PASS`).
4. **To Developer 5 (Evaluation)**:
   - Provide character spans `[text_start, text_end]` and `bbox` `[x0, y0, x1, y1]` for ground-truth IoU evaluation.

---

## 6. Developer 3 Implementation Checklist

- [ ] Define taxonomy and scoring weights in `src/schema/entities.py`
- [ ] Implement deterministic patterns in `src/detection/regex.py`
- [ ] Integrate Presidio + spaCy NER in `src/detection/ner.py`
- [ ] Implement sliding window & table header context injector in `src/detection/context.py`
- [ ] Implement Luhn, Verhoeff, and phone validators in `src/detection/validators.py`
- [ ] Implement span conflict resolver and deduplicator in `src/detection/resolver.py`
- [ ] Write unit tests in `tests/unit/test_detection.py` and `tests/unit/test_resolver.py`
