# Empirical Ablation Study Results
**Generated on**: 2026-10-11 23:13:55

## Experiment Configurations
- **Configuration A (Baseline)**: Regex Patterns only (No NER, No Context Engine, No Validators, No Allow-List).
- **Configuration B (Context-Enhanced Firewall)**: Full 5-Layer Stack (Regex + Presidio/spaCy NER + Context Window Cues + Checksum Validators + Overlap Resolver).

## Empirical Results Table

| Metric | Configuration A (Baseline) | Configuration B (Enhanced) | Absolute Delta |
|---|---|---|---|
| **Overall Recall** | 66.67% | 100.00% | **+33.33%** |
| **Critical PII Recall** | 100.00% | 100.00% | **+0.00%** |
| **Precision** | 100.00% | 93.75% | **-6.25%** |
| **F1 Score** | 80.00% | 96.77% | **+16.77%** |
| **Document Leak Rate** | 100.00% | 0.00% | **-100.00%** |
| **Over-Redaction Rate** | 0.00% | 6.25% | **+6.25%** |

## Key Findings & Security Architecture Validation
1. **Unstructured PII Sensitivity**: Baseline regex missed narrative prose names (`PERSON`) and unstructured residential addresses (`ADDRESS`) that do not conform to fixed digit formats. The integration of Presidio + spaCy NER in Layer 2 completely closed this detection gap.
2. **Context Window Cues**: Ambiguous tokens (e.g. unhyphenated dates of birth or ambiguous PAN/passport codes) were elevated to high confidence by Layer 3's sliding cue windows (`"Date of Birth:"`, `"Tax ID:"`).
3. **Elimination of Document Leaks**: In the Baseline configuration, documents leaked due to undetected names and addresses (**Document Leak Rate: 100.0%**). The Context-Enhanced pipeline brought the Document Leak Rate to **0.0%**, satisfying the fail-closed security objective.
