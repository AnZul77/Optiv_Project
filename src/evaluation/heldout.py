"""
Held-Out Benchmark Evaluation Module
====================================
Executes the production DetectionPipeline against the frozen, never-tuned
out-of-distribution benchmark dataset (data/heldout/) specified in heldout_spec.json.

Returns structured evaluation reports, confusion matrices, and document-level audits.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List

from src.schema.entities import ContentBlock
from src.schema.document import EntityAnnotation
from src.detection.pipeline import DetectionPipeline
from src.evaluation.metrics import generate_report
from src.evaluation.matcher import match_entities

logger = logging.getLogger(__name__)


def load_heldout_spec(project_root: Path) -> Dict[str, Any]:
    spec_path = project_root / "data" / "heldout" / "heldout_spec.json"
    if not spec_path.exists():
        raise FileNotFoundError(f"Benchmark specification not found at {spec_path}")
    with open(spec_path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_heldout_benchmark(project_root: Path = None) -> Dict[str, Any]:
    """
    Executes the frozen held-out benchmark evaluation suite.
    Evaluates 5 unseen documents with 41 ground truth items across 16 taxonomy classes.
    """
    if project_root is None:
        project_root = Path(__file__).resolve().parent.parent.parent

    spec = load_heldout_spec(project_root)
    heldout_dir = project_root / "data" / "heldout"
    doc_ids = spec["test_lock"]["document_ids"]

    pipeline = DetectionPipeline(
        enable_regex=True,
        enable_ner=False,  # High deterministic speed for benchmark test harness
        enable_context=True,
        enable_validators=True,
        enable_allow_list=True,
    )

    predicted_docs: List[List[EntityAnnotation]] = []
    ground_truth_docs: List[List[EntityAnnotation]] = []
    doc_summaries: List[Dict[str, Any]] = []

    for doc_id in doc_ids:
        primary_file = spec["test_lock"]["document_checksums"][doc_id]["primary_file"]
        file_path = heldout_dir / primary_file
        with open(file_path, "r", encoding="utf-8") as f:
            doc_data = json.load(f)

        filename = doc_data["filename"]
        raw_blocks = doc_data["blocks"]
        gt_entities_raw = doc_data["ground_truth_entities"]

        blocks = [
            ContentBlock(
                text=b["text"],
                block_id=b["block_id"],
                page=b["page"],
                section_context=b.get("section_context", ""),
            )
            for b in raw_blocks
        ]

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

        det_result = pipeline.run(blocks=blocks, source_file=filename, document_id=doc_id)

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
            for e in det_result.entities
        ]

        matches = match_entities(pred_annotations, gt_annotations)
        fn_count = matches["counts"]["FN"]
        tp_count = matches["counts"]["TP"]
        fp_count = matches["counts"]["FP"]

        doc_summaries.append({
            "doc_id": doc_id,
            "filename": filename,
            "total_gt": len(gt_annotations),
            "tp": tp_count,
            "fp": fp_count,
            "fn": fn_count,
            "leaked": fn_count > 0,
            "status": "SECURE (0 Leaks)" if fn_count == 0 else f"LEAKED ({fn_count} missed)",
            "missed_tokens": [fn.context.get("raw_value") for fn in matches["FN"]],
        })

        predicted_docs.append(pred_annotations)
        ground_truth_docs.append(gt_annotations)

    report = generate_report(predicted_docs, ground_truth_docs)

    return {
        "spec": spec,
        "report": report,
        "doc_summaries": doc_summaries,
        "total_documents": len(doc_ids),
        "total_entities": report["Total_TP"] + report["Total_FN"],
        "taxonomy_coverage": spec.get("taxonomy_coverage", []),
        "evaluation_contract": spec.get("evaluation_contract", {}),
    }
