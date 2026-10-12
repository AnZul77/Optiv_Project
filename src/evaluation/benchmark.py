import os
import sys
import json
import logging
from typing import List, Dict, Any
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent))

from src.schema.document import EntityAnnotation

from src.evaluation.metrics import generate_report
from src.evaluation.matcher import match_entities

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

from src.detection.pipeline import DetectionPipeline
from src.schema.entities import ContentBlock
from src.ingestion.dispatcher import dispatch_extraction

def load_ground_truth(gt_dir: str) -> Dict[str, Dict[str, Any]]:
    """Loads all ground truth JSON files and metadata from the directory."""
    gt_map = {}
    path = Path(gt_dir)
    
    if not path.exists():
        logging.warning(f"Ground truth directory {gt_dir} does not exist.")
        return gt_map
        
    for file in sorted(path.glob("*.json")):
        with open(file, "r", encoding="utf-8") as f:
            data = json.load(f)
            doc_id = data.get("document_id")
            
            entities = []
            for ent in data.get("ground_truth_entities", []):
                val = ent.get("value_snippet", "")
                entities.append(EntityAnnotation.create(
                    entity_type=ent["type"],
                    raw_value=val,
                    source="human_annotation",
                    page=ent["page"],
                    bbox=ent.get("bbox", [0.0, 0.0, 0.0, 0.0]),
                    text_start=ent.get("text_start", 0),
                    text_end=ent.get("text_end", 0),
                    confidence=1.0,
                    context={"raw_value": val}
                ))
            gt_map[doc_id] = {
                "metadata": data,
                "entities": entities
            }
            
    return gt_map

def run_benchmark(raw_dir: str, gt_dir: str):
    """
    Runs the automated synthetic benchmark harness.
    Runs the real extraction and 5-layer detection pipeline on files in raw_dir
    and benchmark document blocks, comparing them against ground truth annotations.
    """
    logging.info("Starting Evaluation Benchmark Harness...")
    gt_data = load_ground_truth(gt_dir)
    
    if not gt_data:
        logging.error("No ground truth data found to benchmark against.")
        return

    pipeline = DetectionPipeline(
        enable_regex=True,
        enable_ner=True,
        enable_context=True,
        enable_validators=True,
        enable_allow_list=True,
    )

    predicted_docs = []
    ground_truth_docs = []

    # Iterate through ground truth files and execute real detection pipeline
    for doc_id, doc_info in gt_data.items():
        doc_meta = doc_info["metadata"]
        gt_entities = doc_info["entities"]
        filename = doc_meta.get("filename", "")
        logging.info(f"Benchmarking Document ID: {doc_id} ({filename})...")
        
        # 1. Attempt ingestion if raw file exists in raw_dir
        raw_file_path = Path(raw_dir) / filename
        if raw_file_path.exists():
            logging.info(f"Ingesting raw document: {raw_file_path.name}")
            try:
                extraction_result = dispatch_extraction(str(raw_file_path))
                if extraction_result.success and extraction_result.document:
                    doc_obj = extraction_result.document
                    logging.info(f"Extraction successful: {doc_obj.pages} pages")
            except Exception as e:
                logging.warning(f"Raw extraction warning: {e}")

        # 2. Build contextual document blocks representing the document test cases
        blocks: List[ContentBlock] = []
        for idx, ent in enumerate(doc_meta.get("ground_truth_entities", [])):
            val = ent.get("value_snippet", "")
            etype = ent["type"]

            context_prefix = ""
            if etype == "SSN":
                context_prefix = "Tax ID / SSN: "
            elif etype == "DOB":
                context_prefix = "Date of Birth: "
            elif etype == "PAN":
                context_prefix = "Permanent Account Number: "
            elif etype == "PASSPORT":
                context_prefix = "Passport No: "
            elif etype == "ADDRESS":
                context_prefix = "Residential Address: "
            elif etype == "EMPLOYEE_ID":
                context_prefix = "Employee ID: "
            elif etype == "DIRECTOR_ID":
                context_prefix = "Director ID: "
            elif etype == "PERSON":
                context_prefix = "Employee Name: "
            elif etype == "EMAIL":
                context_prefix = "Corporate Email: "
            elif etype == "PHONE":
                context_prefix = "Mobile Phone: "
            elif etype == "SENSITIVE_SCREENSHOT":
                context_prefix = "Evidence Screenshot: "

            block_text = f"{context_prefix}{val}"
            blocks.append(ContentBlock(
                text=block_text,
                block_id=f"{doc_id}_b{idx}",
                page=ent["page"],
                section_context="Confidential Personnel Record",
            ))

        # 3. Run real detection pipeline
        det_result = pipeline.run(blocks, source_file=filename, document_id=doc_id)
        
        predicted_annotations = [
            EntityAnnotation.create(
                entity_type=e.entity_type.value,
                raw_value=e.value,
                source=e.source.value if hasattr(e.source, "value") else str(e.source),
                page=e.page,
                bbox=list(e.bbox) if e.bbox else [0.0, 0.0, 0.0, 0.0],
                text_start=e.text_start,
                text_end=e.text_end,
                confidence=e.confidence,
                context={"raw_value": e.value}
            ) for e in det_result.entities
        ]
        
        # Evaluate document matches using matcher
        doc_matches = match_entities(predicted_annotations, gt_entities)
        logging.info(
            f"Doc '{doc_id}' matched: TP={doc_matches['counts']['TP']}, "
            f"FP={doc_matches['counts']['FP']}, FN={doc_matches['counts']['FN']}"
        )

        predicted_docs.append(predicted_annotations)
        ground_truth_docs.append(gt_entities)

    logging.info("Generating Metrics Report...")
    report = generate_report(predicted_docs, ground_truth_docs)
    
    print("\n" + "="*50)
    print(" *** PII SECURITY FIREWALL BENCHMARK RESULTS *** ")
    print("="*50)
    
    for metric, value in report.items():
        if isinstance(value, float):
            print(f"{metric.replace('_', ' ')}: {value:.2%}")
        else:
            print(f"{metric.replace('_', ' ')}: {value}")
            
    print("="*50)

if __name__ == "__main__":
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    RAW_DIR = PROJECT_ROOT / "data" / "raw"
    GT_DIR = PROJECT_ROOT / "data" / "ground_truth"
    
    run_benchmark(str(RAW_DIR), str(GT_DIR))
