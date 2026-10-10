# Ablation Study Results

## Experiment Configurations
- **Configuration A (Baseline)**: OCR + Basic Regex + Standard NER.
- **Configuration B (Context-Enhanced Firewall)**: OCR + Regex + NER + Context Rules + Checksums + Independent Verifier.

## Results Table

| Metric | Configuration A (Baseline) | Configuration B (Enhanced) | Absolute Improvement |
|--------|---------------------------|----------------------------|----------------------|
| Overall Recall | 60.00% | 100.00% | +40.00% |
| Critical PII Recall | 66.67% | 100.00% | +33.33% |
| Precision | 100.00% | 100.00% | +0.00% |
| F1 Score | 75.00% | 100.00% | +25.00% |
| Document Leak Rate | 100.00% | 0.00% | -100.00% |

## Conclusion
The addition of the Context Engine and Checksum Validators significantly reduced the Document Leak Rate while simultaneously boosting Critical PII Recall.
