"""
CLI Utility to Sanitize an Enterprise Document
==============================================
Usage:
    python scripts/sanitize_document.py <input_file_path> [--output <output_path>]

Runs the complete ingestion -> 5-layer detection -> redaction pipeline
and saves the sanitized artifact to disk (by default in data/outputs/).
"""

import os
import sys
import argparse
from pathlib import Path

# Ensure project root is in sys.path
sys.path.append(str(Path(__file__).parent.parent))

from src.ingestion.dispatcher import route_document
from src.detection.pipeline import DetectionPipeline
from src.sanitization.docx_reconstructor import DOCXReconstructor
from src.sanitization.text_redactor import redact_text_by_values


def sanitize_document(input_path: str, output_path: str = None) -> str:
    input_file = Path(input_path)
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    # Default output directory
    output_dir = Path("data/outputs")
    output_dir.mkdir(parents=True, exist_ok=True)

    file_ext = input_file.suffix.lower()
    if output_path is None:
        if file_ext == ".docx":
            output_file = output_dir / f"sanitized_{input_file.stem}.docx"
        else:
            output_file = output_dir / f"sanitized_{input_file.stem}.txt"
    else:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Step 1: Ingesting '{input_file.name}'...")
    summary = route_document(str(input_file))
    if summary.get("status") != "EXTRACTED":
        raise RuntimeError(f"Ingestion failed: {summary.get('error', 'Unknown Error')}")

    canonical_doc = summary.get("document")
    total_pages = summary.get("total_pages", 1)
    print(f"[+] Ingestion complete: {total_pages} page(s) extracted.")

    print(f"[*] Step 2: Running 5-Layer Detection Pipeline (Regex, NER, Context, Validators, Resolver)...")
    pipeline = DetectionPipeline(enable_ner=True)
    pipeline.run_document(canonical_doc)

    det_summary = canonical_doc.metadata.get("detection_summary", {})
    total_entities = det_summary.get("total_entities", len(canonical_doc.entities))
    risk_summary = det_summary.get("risk_summary", {})
    print(f"[+] Detection complete: {total_entities} entities detected.")
    print(f"    Risk Breakdown: {risk_summary}")

    # Build replacement mapping
    replacements = {}
    for ent in canonical_doc.entities:
        raw_val = ent.context.get("raw_value") if isinstance(ent.context, dict) else ""
        if not raw_val and hasattr(ent, "raw_value"):
            raw_val = getattr(ent, "raw_value")
        if raw_val and raw_val.strip():
            replacements[raw_val] = f"[REDACTED:{ent.type}]"

    print(f"[*] Step 3: Redacting and Reconstructing Artifact...")
    if file_ext == ".docx":
        success, err = DOCXReconstructor.replace_text_in_document(
            str(input_file), str(output_file), replacements
        )
        if not success:
            raise RuntimeError(f"DOCX reconstruction failed: {err}")
    else:
        # Text-based / PDF / PPTX representation
        full_text = []
        for p_num, page in sorted(canonical_doc.pages_dict.items()):
            if page.combined_text.strip():
                full_text.append(f"=== PAGE {p_num} ===\n" + page.combined_text)
        joined = "\n\n".join(full_text)
        sanitized_content = redact_text_by_values(joined, replacements)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(sanitized_content)

    print(f"[SUCCESS] Redacted file saved to: {output_file.resolve()}")
    return str(output_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sanitize an enterprise document")
    parser.add_argument("input", help="Path to the document to sanitize")
    parser.add_argument("--output", "-o", default=None, help="Optional output path")
    args = parser.parse_args()

    sanitize_document(args.input, args.output)
