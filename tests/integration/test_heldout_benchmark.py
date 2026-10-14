"""
Integration Tests: Frozen Held-Out Benchmark Evaluation
======================================================

Evaluates the DetectionPipeline against the frozen, never-tuned held-out
benchmark test split in data/heldout/ according to heldout_spec.json.

Verification Targets:
- Critical PII Recall >= 99% (Target: Zero leaks of SSN, Passport, PAN, Aadhaar, Cards, NINO)
- Overall PII Recall >= 95% across all 16 entity taxonomy classes
- Document Leak Rate == 0.0% (Zero tolerance: no document with unredacted PII)
- False Positive Immunity: Allow-listed operational codes (INC-*, RSK-*, CTL-*, ISO-*) passed cleanly
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any
import pytest

from src.schema.entities import ContentBlock, EntityType
from src.schema.document import EntityAnnotation
from src.detection.pipeline import DetectionPipeline
from src.evaluation.metrics import generate_report
from src.evaluation.matcher import match_entities

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
HELDOUT_DIR = PROJECT_ROOT / "data" / "heldout"
SPEC_FILE = HELDOUT_DIR / "heldout_spec.json"


@pytest.fixture(scope="module")
def benchmark_spec() -> Dict[str, Any]:
    """Load and validate the frozen benchmark specification."""
    assert SPEC_FILE.exists(), f"Benchmark specification not found at {SPEC_FILE}"
    with open(SPEC_FILE, "r", encoding="utf-8") as f:
        spec = json.load(f)
    assert spec["test_lock"]["immutable"] is True
    assert spec["test_lock"]["document_count"] == 5
    return spec


@pytest.fixture(scope="module")
def heldout_documents(benchmark_spec) -> List[Dict[str, Any]]:
    """Loads all 5 frozen held-out benchmark documents."""
    doc_ids = benchmark_spec["test_lock"]["document_ids"]
    docs = []
    for doc_id in doc_ids:
        # Check primary file (heldout_doc_0X.json) or alias
        primary_file = benchmark_spec["test_lock"]["document_checksums"][doc_id]["primary_file"]
        file_path = HELDOUT_DIR / primary_file
        assert file_path.exists(), f"Held-out benchmark document {primary_file} missing!"

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        docs.append(data)

    assert len(docs) == 5, f"Expected 5 heldout benchmark documents, found {len(docs)}"
    return docs


@pytest.fixture(scope="module")
def detection_pipeline() -> DetectionPipeline:
    """Configures production-equivalent DetectionPipeline with fast deterministic execution."""
    return DetectionPipeline(
        enable_regex=True,
        enable_ner=False,  # High deterministic speed for benchmark integration harness
        enable_context=True,
        enable_validators=True,
        enable_allow_list=True,
    )


class TestHeldoutBenchmark:
    """Rigorous evaluation of DetectionPipeline on the frozen held-out benchmark test split."""

    def test_spec_contract_integrity(self, benchmark_spec):
        """Verifies test lock and contract integrity in heldout_spec.json."""
        contract = benchmark_spec["evaluation_contract"]
        assert contract["critical_pii_recall_threshold"] >= 0.99
        assert contract["overall_recall_threshold"] >= 0.95
        assert contract["document_leak_rate_threshold"] == 0.00
        assert len(benchmark_spec["taxonomy_coverage"]) >= 15

    def test_heldout_benchmark_recall_and_leak_rate(
        self, heldout_documents, detection_pipeline, benchmark_spec
    ):
        """
        Executes DetectionPipeline against data/heldout/ and verifies:
        - Critical PII Recall >= 99%
        - Overall Recall >= 95%
        - Document Leak Rate == 0.0%
        """
        predicted_docs: List[List[EntityAnnotation]] = []
        ground_truth_docs: List[List[EntityAnnotation]] = []
        doc_summaries: List[Dict[str, Any]] = []

        contract = benchmark_spec["evaluation_contract"]

        for doc_data in heldout_documents:
            doc_id = doc_data["document_id"]
            filename = doc_data["filename"]
            raw_blocks = doc_data["blocks"]
            gt_entities_raw = doc_data["ground_truth_entities"]

            # 1. Convert JSON blocks into ContentBlocks
            blocks = [
                ContentBlock(
                    text=b["text"],
                    block_id=b["block_id"],
                    page=b["page"],
                    section_context=b.get("section_context", ""),
                )
                for b in raw_blocks
            ]

            # 2. Build Ground Truth EntityAnnotation objects
            gt_annotations = [
                EntityAnnotation.create(
                    entity_type=gt["type"],
                    raw_value=gt["value_snippet"],
                    source="human_annotation",
                    page=gt["page"],
                    text_start=gt.get("text_start", 0),
                    text_end=gt.get("text_end", 0),
                    confidence=1.0,
                    risk=gt.get("risk", "HIGH"),
                    context={"raw_value": gt["value_snippet"]},
                )
                for gt in gt_entities_raw
            ]

            # 3. Run DetectionPipeline
            detection_result = detection_pipeline.run(
                blocks=blocks,
                source_file=filename,
                document_id=doc_id,
            )

            # 4. Convert detected entities to EntityAnnotation objects
            pred_annotations = [
                EntityAnnotation.create(
                    entity_type=e.entity_type.value,
                    raw_value=e.value,
                    source=e.source.value if hasattr(e.source, "value") else str(e.source),
                    page=e.page,
                    bbox=list(e.bbox) if e.bbox else [0.0, 0.0, 0.0, 0.0],
                    text_start=e.text_start,
                    text_end=e.text_end,
                    confidence=e.confidence,
                    risk=e.risk_level.value if hasattr(e.risk_level, "value") else str(e.risk_level),
                    action=e.action.value if hasattr(e.action, "value") else str(e.action),
                    context={"raw_value": e.value},
                )
                for e in detection_result.entities
            ]

            # 5. Evaluate individual document matching
            matches = match_entities(pred_annotations, gt_annotations)
            doc_summaries.append({
                "doc_id": doc_id,
                "tp": matches["counts"]["TP"],
                "fp": matches["counts"]["FP"],
                "fn": matches["counts"]["FN"],
            })

            # Check individual document leak: FN must be 0
            assert matches["counts"]["FN"] == 0, (
                f"Document '{doc_id}' had {matches['counts']['FN']} False Negatives! "
                f"Missed: {[fn.context.get('raw_value') for fn in matches['FN']]}"
            )

            predicted_docs.append(pred_annotations)
            ground_truth_docs.append(gt_annotations)

        # 6. Generate Global Benchmark Evaluation Report
        report = generate_report(predicted_docs, ground_truth_docs)

        # Print formatted summary table for test runner logs
        print("\n" + "=" * 65)
        print(" *** FROZEN HELDOUT BENCHMARK EVALUATION RESULTS *** ")
        print("=" * 65)
        print(f" Total Documents Evaluated : {len(heldout_documents)}")
        print(f" Total Ground Truth Items : {report['Total_TP'] + report['Total_FN']}")
        print(f" True Positives (TP)      : {report['Total_TP']}")
        print(f" False Positives (FP)     : {report['Total_FP']}")
        print(f" False Negatives (FN)     : {report['Total_FN']}")
        print("-" * 65)
        print(f" Critical PII Recall      : {report['Critical_PII_Recall']:.2%} (Threshold: >= {contract['critical_pii_recall_threshold']:.1%})")
        print(f" High-Risk PII Recall     : {report['High_Risk_PII_Recall']:.2%}")
        print(f" Overall PII Recall       : {report['Overall_Recall']:.2%} (Threshold: >= {contract['overall_recall_threshold']:.1%})")
        print(f" Precision                : {report['Precision']:.2%}")
        print(f" F1-Score                 : {report['F1_Score']:.2%}")
        print(f" Document Leak Rate       : {report['Document_Leak_Rate']:.2%} (Threshold: == {contract['document_leak_rate_threshold']:.1%})")
        print(f" Over-Redaction Rate      : {report['Over_Redaction_Rate']:.2%}")
        print("=" * 65)

        # 7. Core Benchmark Contract Assertions
        assert report["Critical_PII_Recall"] >= contract["critical_pii_recall_threshold"], (
            f"Critical PII Recall {report['Critical_PII_Recall']:.2%} below required "
            f"{contract['critical_pii_recall_threshold']:.2%}"
        )

        assert report["Overall_Recall"] >= contract["overall_recall_threshold"], (
            f"Overall Recall {report['Overall_Recall']:.2%} below required "
            f"{contract['overall_recall_threshold']:.2%}"
        )

        assert report["Document_Leak_Rate"] == contract["document_leak_rate_threshold"], (
            f"Document Leak Rate {report['Document_Leak_Rate']:.2%} violated zero tolerance requirement!"
        )

    def test_allow_list_suppression_on_heldout_data(
        self, heldout_documents, detection_pipeline
    ):
        """
        Verifies that operational business codes and tickets in held-out documents
        (INC-2026-0417, RSK-001, CTL-IAM-004, ISO-27001) are never flagged as PII.
        """
        for doc_data in heldout_documents:
            allow_tokens = doc_data.get("allow_listed_tokens", [])
            if not allow_tokens:
                continue

            blocks = [
                ContentBlock(
                    text=b["text"],
                    block_id=b["block_id"],
                    page=b["page"],
                    section_context=b.get("section_context", ""),
                )
                for b in doc_data["blocks"]
            ]

            det_result = detection_pipeline.run(blocks, source_file=doc_data["filename"])
            detected_values = [e.value for e in det_result.entities]

            for token in allow_tokens:
                for val in detected_values:
                    assert token not in val, f"Allow-listed code '{token}' was mistakenly flagged as PII: '{val}'"
