# Empirical Ablation Study Results
**Generated on**: Live Session Benchmark

## Experiment Configurations
- **Configuration A (Baseline)**: Regex Patterns only (No NER, No Context Engine, No Validators, No Allow-List).
- **Configuration B (Context-Enhanced Firewall)**: Full 5-Layer Stack (Regex + Presidio/spaCy NER + Context Window Cues + Checksum Validators + Overlap Resolver).

## Empirical Results Table

| Metric | Configuration A (Baseline) | Configuration B (Enhanced) | Absolute Delta |
|---|---|---|---|
| **Overall Recall** | 61.40% | 87.72% | **+26.32%** |
| **Critical PII Recall** | 85.71% | 100.00% | **+14.29%** |
| **Precision** | 97.22% | 90.91% | **-6.31%** |
| **F1 Score** | 75.27% | 89.29% | **+14.02%** |
| **Pre-Gate Unredacted Exposure** | 100.00% | 62.50% | **-37.50%** |
| **Downstream LLM Leak Rate (Gate)** | 100.00% (High Leak) | **0.00% (Zero Leaks)** | **-100.00%** |
| **Over-Redaction Rate** | 2.78% | 9.09% | **+6.31%** |

## Key Findings & Security Architecture Validation
1. **Unstructured PII Sensitivity**: Baseline regex missed narrative prose names (`PERSON`) and unstructured residential addresses (`ADDRESS`) that do not conform to fixed digit formats. The integration of Presidio + spaCy NER in Layer 2 completely closed this detection gap.
2. **Context Window Cues**: Ambiguous tokens (e.g. unhyphenated dates of birth or ambiguous PAN/passport codes) were elevated to high confidence by Layer 3's sliding cue windows (`"Date of Birth:"`, `"Tax ID:"`).
3. **Elimination of Document Leaks**: In the Baseline configuration, 100% of documents leaked PII downstream. In the Context-Enhanced architecture, our **Fail-Closed Security Gate and Independent Secondary Verifier** intercepts any residual PII or uncertainty, bringing the Downstream LLM Leak Rate to **0.0% (Zero)**.
