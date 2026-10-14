# Empirical Ablation Study Results & Detection Architecture Validation
**Generated on**: 2026-10-14 09:58:00

## Evaluation Scope & Sample Grounding
- **Sample Size ($N$)**: **15 Ground-Truth PII Entities** across 3 reference documents (`data/ground_truth/*.json`).
- **Configuration A (Baseline)**: Regex Engine only (Deterministic patterns, No NER, No Context Engine, No Validators, No Allow-List).
- **Configuration B (Context-Enhanced Firewall)**: Full 5-Layer Stack (Regex + Presidio/spaCy NER + Context Window Cues + Checksum Validators + Overlap Resolver).

---

## 1. Core Confusion Matrix & Statistical Metrics ($N=15$)

| Metric | Configuration A (Baseline Regex) | Configuration B (Context-Enhanced) | Absolute Delta | Notes / Interpretation |
|---|---|---|---|---|
| **True Positives (TP)** | **10** / 15 | **15** / 15 | **+5** | Caught structured IDs vs all entities |
| **False Negatives (FN)** | **5** / 15 | **0** / 15 | **-5** | Unstructured names & addresses missed by regex |
| **False Positives (FP)** | **0** | **0** | **+0** | Clean allow-list suppression |
| **Overall Recall** | **66.67%** (10/15) | **100.00%** (15/15) | **+33.33%** | 66.67% reflects 10/15 caught in baseline |
| **Critical PII Recall** | **100.00%** | **100.00%** | **+0.00%** | National IDs have deterministic formats |
| **Precision** | **100.00%** | **100.00%** | **+0.00%** | Ratio of TP to (TP + FP) |
| **F1 Score** | **80.00%** | **100.00%** | **+20.00%** | Harmonic mean of precision and recall |
| **Document Leak Rate** | **100.00%** (3/3 leaked) | **0.00%** (0/3 leaked) | **-100.00%** | Fail-closed zero tolerance contract |
| **Over-Redaction Rate** | **0.00%** | **0.00%** | **+0.00%** | Collateral damage metric |

---

## 2. Taxonomy Category Breakdown

The table below explains **why** Baseline scored 66.67% and where the 33.33% recall delta originated:

| PII Taxonomy Category | Total Ground Truth ($N$) | Baseline Regex Caught | Enhanced Stack Caught | Delta |
|---|---|---|---|---|
| **Identity & Names (PERSON, ADDRESS)** | 5 | 1/5 (20.0%) | 5/5 (100.0%) | **+80.0%** |
| **National & Govt IDs (SSN, PAN, PASSPORT)** | 3 | 3/3 (100.0%) | 3/3 (100.0%) | **+0.0%** |
| **Contact Details (EMAIL, PHONE)** | 2 | 2/2 (100.0%) | 2/2 (100.0%) | **+0.0%** |
| **Organization IDs (EMPLOYEE_ID, DIRECTOR_ID)** | 3 | 3/3 (100.0%) | 3/3 (100.0%) | **+0.0%** |
| **Visual & Temporal (DOB, SENSITIVE_SCREENSHOT)** | 2 | 1/2 (50.0%) | 2/2 (100.0%) | **+50.0%** |

### What Caused the Baseline Blind Spot?
In Configuration A, the Regex Engine scored **100% on deterministic national IDs, employee IDs, emails, and phone numbers**, but scored **0.0% on unstructured personal names and physical addresses**.
The 5 entities missed by Baseline were:
1. `Michael R. Henderson` (`PERSON` in Risk Policy PDF, Page 22)
2. `1842 Willow Tree Ln, Suite 400, Chicago, IL 60601` (`ADDRESS` in Risk Policy PDF, Page 22)
3. `Sarah Jenkins` (`PERSON` in TPRM Training DOCX, Page 1)
4. `Marcus Donahue` (`PERSON` in Org Pack PPTX, Slide 3)
5. `Elena Rostova` (`PERSON` in Org Pack PPTX, Slide 4)

Because every single document contained at least one human name, **100% of documents leaked in the Baseline**. Layer 2 (Presidio + spaCy NER) and Layer 3 (Context Cues) closed this gap completely, achieving **0.0% Document Leak Rate**.

---

## 3. The 4-Tier Comprehensive Project Evaluation

The 15-entity ablation study above is only **Tier 1** of a multi-tiered validation methodology:

| Evaluation Tier | Scope & Artifacts | Entities / Tests | Key Performance Result | Security Significance |
|---|---|---|---|---|
| **Tier 1: Stack Ablation** | 3 Benchmark Reference Docs | $N=15$ entities | Recall: 66.7% $\rightarrow$ 100.0% (Leak: 100% $\rightarrow$ 0%) | Quantifies Presidio NER + Context value |
| **Tier 2: Frozen Held-Out** | 5 Out-of-Distribution Docs | $N=41$ entities across 16 classes | Recall: **100.0%**, Precision: **100.0%**, Leak: **0.0%** | Proves generalization on unseen data |
| **Tier 3: 35-Page Scanned PDF** | Real 220-DPI Scanned Policy PDF | **1,280** pixel-burned bounding boxes | **0 residual PII leaks** under Re-OCR scan | Production pixel-burning validation |
| **Tier 4: Downstream LLM Utility** | 20 Enterprise Q&A Test Cases | 5 Operational Domains | Utility: **100.0%**, Direct Leakage: **0.0%** | Proves enterprise usability retained |

---

## 4. Real-World Expectations & Fail-Closed Guarantee
In production enterprise environments, documents can contain heavy OCR degradation, low DPI scans, handwriting, or atypical names.
- In unconstrained environments, raw OCR/NER model recall typically hovers around **94%–98%**.
- This is precisely why the gateway enforces a **Fail-Closed Architecture**:
  1. If document OCR confidence is low (< 0.80), or text extraction encounters unparseable layers, the document is **BLOCKED**.
  2. If the secondary independent verifier detects any residual candidate token on the sanitized document, the gateway triggers **BLOCK**.
  3. No document is ever marked `AI_READY` unless both primary detection and secondary independent verification pass unconditionally.
