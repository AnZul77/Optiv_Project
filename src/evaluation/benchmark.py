import os
import sys
import json
import logging
from typing import List, Dict, Any
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent))

from src.schema.document import EntityAnnotation

from src.evaluation.metrics import generate_report

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def load_ground_truth(gt_dir: str) -> Dict[str, List[EntityAnnotation]]:
    """Loads all ground truth JSON files from the directory."""
    gt_map = {}
    path = Path(gt_dir)
    
    if not path.exists():
        logging.warning(f"Ground truth directory {gt_dir} does not exist.")
        return gt_map
        
    for file in path.glob("*.json"):
        with open(file, "r") as f:
            data = json.load(f)
            doc_id = data.get("document_id")
            
            entities = []
            for ent in data.get("ground_truth_entities", []):
                entities.append(EntityAnnotation.create(
                    entity_type=ent["type"],
                    raw_value=ent.get("value_snippet", ""),
                    source="human_annotation",
                    page=ent["page"],
                    bbox=ent.get("bbox"),
                    text_start=ent.get("text_start", 0),
                    text_end=ent.get("text_end", 0),
                    confidence=1.0
                ))
            gt_map[doc_id] = entities
            
    return gt_map

def run_benchmark(raw_dir: str, gt_dir: str):
    """
    Runs the automated synthetic benchmark harness.
    In a fully integrated state, this would run the extraction and detection 
    pipelines on files in raw_dir and compare them against gt_dir.
    """
    logging.info("Starting Evaluation Benchmark Harness...")
    gt_data = load_ground_truth(gt_dir)
    
    if not gt_data:
        logging.error("No ground truth data found to benchmark against.")
        return

    predicted_docs = []
    ground_truth_docs = []

    # Iterate through ground truth files and simulate pipeline predictions
    for doc_id, gt_entities in gt_data.items():
        logging.info(f"Benchmarking Document ID: {doc_id}...")
        
        # Here we would normally call:
        # doc = route_document(file_path)
        # However, because the detection stack (Developer 3) is not fully merged,
        # we will simulate the predictions for testing the benchmark harness itself.
        
        # Simulate a 90% perfect prediction (miss one entity occasionally)
        simulated_predictions = gt_entities[:-1] if len(gt_entities) > 1 else gt_entities
        
        predicted_docs.append(simulated_predictions)
        ground_truth_docs.append(gt_entities)

    logging.info("Generating Metrics Report...")
    report = generate_report(predicted_docs, ground_truth_docs)
    
    print("\n" + "="*50)
    print(" 🏆 PII SECURITY FIREWALL BENCHMARK RESULTS 🏆 ")
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
