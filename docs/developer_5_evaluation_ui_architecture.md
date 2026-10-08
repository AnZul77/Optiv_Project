# Developer 5: Evaluation Benchmark, Adversarial Testing & UI Architecture Guide

**Role:** Person 5 — Evaluation Benchmark, Adversarial Testing & UI Lead  
**Domain:** Empirical Evaluation, Ground-Truth Annotation, Synthetic Dataset Generation, Adversarial Testing Suites, Ablation Studies, and Streamlit Dashboard  
**Key Modules:** `src/evaluation/matcher.py`, `src/evaluation/metrics.py`, `src/evaluation/benchmark.py`, `src/evaluation/ablation.py`, `app.py`, `tests/adversarial/`  

---

## 1. Role Purpose & Core Security Mandate

Developer 5 is responsible for the **scientific validation, adversarial stress-testing, and user interface** of the PII Security Firewall.

In an enterprise security deployment:
1. **Empirical Proof**: The team cannot simply claim the firewall works; Developer 5 rigorously measures performance against frozen ground-truth datasets, demonstrating that the system meets enterprise targets ($\ge 99\%$ Critical PII recall, **0 Document Leak Rate**).
2. **Adversarial Resilience**: Attackers and untrusted users intentionally construct adversarial payloads (homoglyphic substitutions, zero-width spaces, character spacing, rotated scans) to evade regex and NER models. Developer 5 builds and executes the adversarial test harness.
3. **Executive & Operational UI**: Developer 5 builds the interactive Streamlit dashboard (`app.py`) allowing security analysts and auditors to visualize document processing, inspect bounding boxes, verify burned pixels, review audit logs, and observe the fail-closed gate.

---

## 2. Target Performance & Acceptance Metrics

Developer 5 calculates and validates the following acceptance metrics:

| Metric | Target | Formula / Definition |
|---|---|---|
| **Critical PII Recall** | $\ge 99\%$ | $\frac{TP_{\text{crit}}}{TP_{\text{crit}} + FN_{\text{crit}}}$ on frozen test set |
| **High-Risk PII Recall** | $\ge 99\%$ | $\frac{TP_{\text{high}}}{TP_{\text{high}} + FN_{\text{high}}}$ on frozen test set |
| **Overall PII Recall** | $\ge 95\%$ | $\frac{TP}{TP + FN}$ across all entity classes |
| **Document Leak Rate** | **0 (Zero Tolerance)** | $\frac{\text{Documents with } \ge 1 \text{ unredacted PII}}{\text{Total Test Documents}}$ |
| **Over-Redaction Rate** | $< 10\%$ | $\frac{\text{False Positive Redactions}}{\text{Total Redactions}}$ |
| **Structure Retention** | $\ge 80\%$ | Preserved layout formatting / Original layout formatting |
| **Low-Confidence Critical Pass** | **0 (Strict)** | Zero low-confidence regions allowed through gate |
| **Verifier Bypass Rate** | **0 (Strict)** | Zero verifier residual alerts permitted past gate |

---

## 3. Directory & Module Specifications

```
app.py                         # Streamlit Security Gateway UI
src/
└── evaluation/
    ├── __init__.py            # Package exports
    ├── matcher.py             # Bounding-box IoU & text offset span matcher
    ├── metrics.py             # Precision, recall, F1, leak rate, over-redaction
    ├── benchmark.py           # Automated evaluation harness
    └── ablation.py            # Baseline vs. improved context ablation runner
tests/
└── adversarial/
    ├── __init__.py
    ├── test_evasion.py        # Spaced text, zero-width chars, homoglyphs
    ├── test_corrupt_files.py  # Blurry scans, low-contrast, rotated pages
    └── test_leak_injection.py # Deliberate PII leaks to verify fail-closed blocking
data/
├── ground_truth/              # Frozen ground-truth annotations
├── synthetic/                 # Synthetic generated documents
└── heldout/                   # Untuned frozen test split
```

---

## 4. Detailed Component Technical Requirements

### 4.1 Span & Bounding Box Matcher (`src/evaluation/matcher.py`)
- Evaluates predicted `EntityAnnotation` against ground-truth annotations:
  - **Text Match**: Exact or partial character span overlap ($\text{IoU}_{\text{char}} \ge 0.50$).
  - **Spatial Match**: Bounding box Intersection-over-Union ($\text{IoU}_{\text{bbox}} \ge 0.50$).
- Tags predictions as True Positive ($TP$), False Positive ($FP$), or False Negative ($FN$).

### 4.2 Metrics Calculator (`src/evaluation/metrics.py`)
- Computes Precision, Recall, F1 score per entity type (`SSN`, `EMAIL`, `PERSON`, `PAN`, etc.).
- Calculates **Document Leak Rate**: A document is counted as leaked if even a single ground-truth PII entity was neither redacted nor blocked.
- Calculates **Over-Redaction Rate**: Penalizes aggressive models that redact non-sensitive business terms (e.g. policy IDs).

### 4.3 Ablation Study Runner (`src/evaluation/ablation.py`)
- Compares two pipeline configurations:
  - **Configuration A (Baseline)**: OCR + Basic Regex + Standard NER.
  - **Configuration B (Context-Enhanced Firewall)**: OCR + Regex + NER + Context Rules + Checksums + Independent Verifier.
- Outputs formal LaTeX / Markdown ablation tables in `reports/evaluation/ablation_results.md`.

### 4.4 Adversarial Attack Suite (`tests/adversarial/`)
- Tests four evasion vectors:
  1. **Character Spacing**: Injected whitespace (e.g., `S S N : 1 2 3 - 4 5 - 6 7 8 9`).
  2. **Zero-Width Spaces**: Concealed Unicode separators (e.g., `J\u200bo\u200bh\u200bn`).
  3. **Homoglyphs**: Cyrillic / Greek visually identical letters substituting Latin characters.
  4. **Rotated / Skewed Scans**: Documents rotated by 90° or blurred scans.
- Verifies that any adversarial attempt that bypasses Developer 3 is caught by Developer 4's verifier and results in **BLOCK**.

### 4.5 Streamlit Security Dashboard (`app.py`)
- **Interactive UI Sections**:
  1. **Header & Status Banner**: Gateway title, operational status, security profile.
  2. **Document Upload**: Multi-format file uploader supporting PDF, DOCX, and PPTX.
  3. **Pipeline Progress Bar**: Real-time feedback through Extraction $\rightarrow$ Detection $\rightarrow$ Redaction $\rightarrow$ Verification $\rightarrow$ Gate Decision.
  4. **Visual Side-by-Side Comparison**:
     - Left: Original page with highlighted detection bounding boxes.
     - Right: Sanitized document page with permanently burned black boxes.
  5. **Gatekeeper Decision Card**:
     - Large green badge: `AI READY: PASS` (Safe for LLM consumption).
     - Large red badge: `BLOCKED: HIGH RISK / UNVERIFIED` (Rejected).
  6. **Telemetry & Audit Trail Table**: View salted-hash audit records, entity counts, latency metrics.
  7. **Download Action**: Button to download verified sanitized artifact.

---

## 5. Integration Contracts with Other Developers

1. **From Developer 1**:
   - Call `route_document(uploaded_file)` from `app.py` and benchmark scripts.
2. **From Developer 2 & 4**:
   - Consume before-and-after image byte streams for side-by-side visual display in Streamlit.
3. **From Developer 3**:
   - Access `CanonicalDocument.entities` for span matching and metric computation.
4. **From Developer 4**:
   - Consume `gate_decision` (`PASS` vs `BLOCK`) and audit logs for display in the dashboard.

---

## 6. Developer 5 Implementation Checklist

- [ ] Catalog 3 Cadence artifacts and create frozen ground truth in `data/ground_truth/`
- [ ] Implement spatial and text span matcher in `src/evaluation/matcher.py`
- [ ] Implement metric evaluation formulas in `src/evaluation/metrics.py`
- [ ] Build automated synthetic benchmark harness in `src/evaluation/benchmark.py`
- [ ] Implement formal ablation experiment runner in `src/evaluation/ablation.py`
- [ ] Implement adversarial test cases in `tests/adversarial/`
- [ ] Build complete Streamlit security dashboard in `app.py`
- [ ] Generate evaluation benchmark report and confusion matrices in `reports/evaluation/`
