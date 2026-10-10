# Developer 4: Security Policy, Independent Verification & Audit Architecture Guide

**Role:** Person 4 — Security Policy & Independent Verifier Lead  
**Domain:** Policy Enforcement Engine, Risk Aggregation, Independent Secondary Verifier, Fail-Closed Gateway Gate, and Zero-PII Audit Logging  
**Key Modules:** `config/policy.yaml`, `src/policy/risk.py`, `src/policy/policy.py`, `src/sanitization/text_redactor.py`, `src/verification/verifier.py`, `src/verification/residual_scan.py`, `src/verification/gate.py`, `src/audit/logger.py`  

---

## 1. Role Purpose & Core Security Mandate

Developer 4 is the **authoritative security boundary enforcer** of the PII Security Firewall. Developer 4 ensures that no document ever reaches downstream AI/LLM systems with unredacted or unverified PII.

### Core Principles Enforced by Developer 4:
1. **Independent Verification Boundary**:
   - The verifier **must** run an independent, heterogeneous secondary detection stack decoupled from Developer 3's primary detector.
   - If the primary detector used Presidio + standard regex, the verifier must employ an alternate stack (e.g., digit-run entropy detectors, alternate regex dictionaries, character-spacing heuristic scans).
   - *Rule:* A detector's blind spot must never be verified by its own logic.
2. **Strict Fail-Closed Architecture**:
   - `AI_READY = TRUE` is strictly forbidden unless the document satisfies zero unresolved critical/high-risk PII detections and zero verification residual alerts.
   - If an extractor errors, OCR confidence is low ($\le 0.60$), or the verifier raises an alert $\rightarrow$ **BLOCK**.
3. **Zero-PII Salted Hash Audit Trail**:
   - Audit logs record entity IDs, entity types, page numbers, spatial bounding boxes, actions (`REDACTED`, `BLOCKED`, `ALLOWED`), and salted SHA-256 hashes (`value_hash`). Plaintext PII is **never** written to disk or logs.

---

## 2. Directory & Module Specifications

```
config/
└── policy.yaml               # Policy configuration: thresholds, actions, allow-lists
src/
├── policy/
│   ├── __init__.py           # Package exports
│   ├── risk.py               # Inherent vs. residual risk scoring (Critical Dominance rule)
│   └── policy.py             # YAML policy engine parser & action evaluator
├── sanitization/
│   └── text_redactor.py      # Native text redaction engine ([REDACTED_TYPE] / solid block)
├── verification/
│   ├── __init__.py           # Package exports
│   ├── residual_scan.py      # Secondary re-OCR feed processor for sanitized files
│   ├── verifier.py           # Independent secondary detection engine
│   └── gate.py               # Fail-closed AI Readiness gatekeeper
└── audit/
    ├── __init__.py           # Package exports
    └── logger.py             # Cryptographic zero-PII audit logger
```

---

## 3. Detailed Component Technical Requirements

### 3.1 Policy Engine & Risk Model (`config/policy.yaml`, `src/policy/risk.py`, `src/policy/policy.py`)
- **`config/policy.yaml` Specification**:
  ```yaml
  version: "1.0"
  rules:
    CRITICAL:
      entities: ["SSN", "PASSPORT", "PAN", "AADHAAR", "CARD", "TAX_ID"]
      action: "REDACT"
      min_confidence_to_redact: 0.50
      uncertainty_action: "BLOCK"
    HIGH:
      entities: ["EMAIL", "PHONE", "PERSON", "ADDRESS", "DOB"]
      action: "REDACT"
      min_confidence_to_redact: 0.70
    MEDIUM:
      entities: ["EMPLOYEE_ID", "DIRECTOR_ID"]
      action: "REDACT"
      min_confidence_to_redact: 0.80

  allow_lists:
    business_codes:
      - "^INC-\\d{4}-\\d+$"
      - "^RSK-\\d+$"
      - "^GRP-POL-\\d+$"
      - "^CTL-IAM-\\d+$"

  gate:
    fail_closed: true
    max_allowed_residual_risk: "NONE"
    min_page_ocr_confidence: 0.60
  ```

- **Critical Dominance Risk Scoring (`src/policy/risk.py`)**:
  - **Inherent Risk**: The maximum risk level across all detected entities before redaction. If even one `SSN` is present, inherent risk is `CRITICAL`.
  - **Residual Risk**: The risk remaining after redaction and verification. If any high/critical entity could not be verified as cleanly sanitized, residual risk remains `CRITICAL`.

### 3.2 Native Text Redactor (`src/sanitization/text_redactor.py`)
- Replaces detected sensitive character spans with standardized redaction tokens:
  - Format: `[REDACTED_{TYPE}]` (e.g. `[REDACTED_SSN]`, `[REDACTED_EMAIL]`).
  - Optional mode: Solid block character masking (`█████████`).
- Preserves document layout structure ($\ge 80\%$ structural formatting retention) so utility is maintained for downstream LLMs.

### 3.3 Independent Secondary Verifier (`src/verification/verifier.py`)
- **Decoupled Architecture**:
  - Independent regular expressions targeting common PII patterns with loose boundary matching.
  - **Digit-Run Entropy Heuristic**: Computes Shannon entropy on contiguous numeric strings (detects masked or unformatted SSNs and card numbers missed by strict regex).
  - **Adversarial Spacing Detector**: Detects spaced tokens (e.g., `S S N : 1 2 3 - 4 5 - 6 7 8 9` or `R a h u l`).

### 3.4 Re-OCR Residual Scanner (`src/verification/residual_scan.py`)
- Consumes the post-redaction visual images and re-OCRed text feeds from Developer 2.
- Scans re-OCRed visual text to confirm that previously burned boxes completely obliterated underlying characters.
- If the re-OCR engine can read even a partial fragment of a redacted passport or SSN $\rightarrow$ flag as `RESIDUAL_LEAK_DETECTED`.

### 3.5 Fail-Closed AI Readiness Gate (`src/verification/gate.py`)
- **Evaluation Criteria**:
  ```python
  class AIReadinessGate:
      def evaluate(
          self,
          document: CanonicalDocument,
          verifier_report: VerificationReport,
          ocr_confidences: Dict[int, float]
      ) -> GateDecision:
          """
          Pass Criteria:
          1. Zero unredacted critical/high PII entities
          2. Verifier reported zero residual leaks
          3. All pages have OCR confidence >= min_page_ocr_confidence
          4. Zero security limit violations (input safety report clean)
          
          Otherwise:
          Decision: BLOCK (Fail-Closed)
          """
  ```

### 3.6 Salted-Hash Audit Logger (`src/audit/logger.py`)
- Writes structured JSONL records to `data/outputs/audit.log`.
- Record structure:
  ```json
  {
    "timestamp": "2026-10-08T16:45:00Z",
    "document_id": "doc-uuid-1234",
    "filename": "Risk_Policy_2026.pdf",
    "entity_id": "urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "type": "SSN",
    "value_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "page": 22,
    "bbox": [120.0, 450.0, 310.0, 490.0],
    "action": "REDACTED",
    "gate_decision": "PASS"
  }
  ```

---

## 4. Inputs Consumed from Developer 1 & Other Developers

1. **From Developer 1**:
   - `CanonicalDocument`: Page blocks, metadata, and structural content.
   - `MetadataSanitizer`: Calls property sanitizers before document release.
   - `InputSafetyGuard`: Integrates prompt injection isolation report into the gate evaluation.
2. **From Developer 2**:
   - Sanitized image byte streams and re-OCR residual text streams.
3. **From Developer 3**:
   - Detected candidate `EntityAnnotation` objects.

---

## 5. Developer 4 Implementation Checklist

- [x] Author `config/policy.yaml` with rules, actions, and allow-lists
- [x] Implement risk scoring and critical dominance rules in `src/policy/risk.py`
- [x] Implement policy engine evaluator in `src/policy/policy.py`
- [x] Implement text redaction in `src/sanitization/text_redactor.py`
- [x] Implement independent secondary verifier in `src/verification/verifier.py`
- [x] Implement re-OCR residual scanner in `src/verification/residual_scan.py`
- [x] Implement fail-closed AI Readiness gate in `src/verification/gate.py`
- [x] Implement zero-PII salted-hash audit logger in `src/audit/logger.py`
- [x] Write unit tests in `tests/unit/test_policy.py`, `tests/unit/test_verifier.py`, and `tests/unit/test_gate.py`
      (plus `test_text_redactor.py`, `test_residual_scan.py`, `test_audit_logger.py`, `test_output_scanner.py`
      and `tests/integration/test_security_checkpoint.py`)
- [x] Security checkpoint orchestrator `src/verification/checkpoint.py` (policy → redact → verify → gate → audit)
- [x] LLM output scanner `src/verification/output_scanner.py` (Day 18, second security boundary)
- [x] `docs/threat_model.md`: threat model, security boundary, policy guide, block codes (Day 1 / Day 21)
- [x] Demo: `python scripts/dev4_security_checkpoint_demo.py`

---

## 6. Integration Hooks (how other developers plug in)

Everything below is additive. No existing module was modified.

| From | What to call | Notes |
|---|---|---|
| **Dev 3** (detection) | `SecurityCheckpoint().run(blocks, detection_result, filename=...)` | `blocks` = the `ContentBlock`s given to `DetectionPipeline.run()`. Offsets are block-relative, so each entity needs its `block_id`. |
| **Dev 3** (CanonicalDocument path) | `DetectionPipeline.run_document()` currently drops `block_id` when it converts `PIIEntity` → `EntityAnnotation`. Adding `"block_id": entity.block_id` to the `context` dict there is enough: the redactor already reads `context["block_id"]`. Until then, document-level redaction blocks with `REDACTION_INCOMPLETE` (fail-closed). | One-line change, Dev 3's call. |
| **Dev 2** (OCR / pixel burning) | `ResidualScanner.from_policy().scan_pages(page_images, page_boxes)` | `page_boxes` is the same map passed to `redact_scanned_pdf()`. Single result dicts from `src.ocr.residual_scan.scan_residual()` go to `evaluate_ocr_result(result, redacted_boxes=...)`. Pass the reports to `checkpoint.run(..., residual_reports=[...])`. |
| **Dev 2** (OCR confidence) | `checkpoint.run(..., ocr_confidences={page: conf})` | Any page ≤ 0.60 blocks. |
| **Dev 1** (DOCX rebuild) | `TextRedactor().build_docx_replacements(blocks, entities)` → `DOCXReconstructor.replace_text_in_document(src, dst, replacements)` | Then `checkpoint.run(..., integrity_result=DocumentIntegrityGuard.verify_document(dst))`. |
| **Dev 1** (pre-flight rejections) | `AuditLogger.from_policy().log_security_event(doc_id, filename, "ZIP_BOMB_DETECTED", detail)` | Codes from `docs/architecture.md` §4. |
| **Dev 5** (UI) | `result.gate_decision.label` (`"AI READY: PASS"`), `result.to_dict()`, `AuditLogger.from_policy().read_records(limit=50)` | All UI-safe: no raw PII. Release text only via `result.llm_payload` / `result.sanitized_blocks` (empty when blocked). |
| **Dev 5** (adversarial tests) | `from src.verification.verifier import verify_document` → `verify_document(text).passed` | Drop-in for the `mock_verifier` in `tests/adversarial/test_evasion.py`. |
| **Dev 5** (Day 15 compliance) | `audit_compliance_check(log_path, ground_truth_values)` | Confirms zero raw PII in the audit log. |

### Remaining Dev 4 roadmap items (need other modules first)

- [ ] **Day 14:** joint end-to-end smoke test on the three Cadence files (needs Dev 3's `block_id` hand-off and Dev 2's re-OCR on real pages).
- [ ] **Day 15:** run `audit_compliance_check()` over a full benchmark run with the frozen ground-truth values.
- [ ] **Day 19:** wire the gate banner, audit table and policy view into `app.py` (Dev 5 owns the layout; the APIs above are ready).
- [ ] Production: set `PII_FIREWALL_AUDIT_SALT`, and flip `gate.require_integrity_check: true` once sanitized files are produced.
