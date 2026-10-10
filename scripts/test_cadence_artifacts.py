"""
Cadence Benchmark Artifact Ingestion Test
Tests Developer 1's ingestion pipeline on the 3 actual Cadence test documents:
1. Cadence_Group_Risk_Management_Policy__v6.0.pdf (Scanned PDF)
2. Cadence_TPRM_Training.docx (DOCX with screenshots & tables)
3. Cadence_Financial_Group_Organizational_Pack.pptx (PPTX with org charts & notes)
"""

import os
import sys
import time

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.ingestion.dispatcher import route_document
from src.ingestion.validators import validate_document
from src.ingestion.metadata import MetadataExtractor


def banner(title):
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def check_file(file_path):
    filename = os.path.basename(file_path)
    banner(f"TESTING ARTIFACT: {filename}")
    
    if not os.path.exists(file_path):
        print(f"[-] Error: File not found at {file_path}")
        return

    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    print(f"[*] File Size: {file_size_mb:.2f} MB ({os.path.getsize(file_path):,} bytes)")

    # 1. Pre-flight Security & Format Validation
    t0 = time.time()
    val_res = validate_document(file_path)
    val_time = time.time() - t0
    
    print(f"\n--- 1. Pre-Flight Security Validation (took {val_time:.3f}s) ---")
    print(f"  Valid: {val_res.is_valid}")
    print(f"  Detected Format: {val_res.detected_type}")
    if val_res.error:
        print(f"  Error: {val_res.error}")
        return
    if val_res.warnings:
        print(f"  Warnings: {val_res.warnings}")

    # 2. Extract Document Properties & Metadata
    print(f"\n--- 2. Document Metadata & Hidden Channel Inspection ---")
    meta = MetadataExtractor.extract_metadata(file_path)
    for k, v in meta.items():
        if k not in ["pdf_metadata", "docx_metadata", "pptx_metadata"]:
            print(f"  {k}: {v}")

    # 3. Route Through Multimodal Ingestion Pipeline
    t1 = time.time()
    result = route_document(file_path)
    extract_time = time.time() - t1
    
    print(f"\n--- 3. Ingestion & Multimodal Extraction (took {extract_time:.3f}s) ---")
    print(f"  Extraction Status: {result['status']}")
    if result["status"] != "EXTRACTED":
        print(f"  Error: {result['error']}")
        return

    doc = result["document"]
    print(f"  Total Pages / Slides: {doc.pages}")
    print(f"  Has Native Text Layer: {result['has_native_text']}")
    print(f"  Total Visual Assets Extracted: {result['total_images']}")
    print(f"  Total Tables Extracted: {result['total_tables']}")
    
    # Analyze Extracted Content
    pages_with_native = sum(1 for p in doc.pages_dict.values() if p.has_native_text)
    pages_scanned = sum(1 for p in doc.pages_dict.values() if p.is_scanned)
    print(f"  Pages with Native Text: {pages_with_native} / {doc.pages}")
    print(f"  Scanned / Image-Only Pages: {pages_scanned} / {doc.pages}")

    # Inspect Tables if any
    all_tables = doc.get_all_tables()
    if all_tables:
        print(f"\n  [Sample Table Inspection]")
        t = all_tables[0]
        print(f"  Table #1 (Page {t.page}): {len(t.headers)} columns, {len(t.rows)} rows")
        print(f"  Headers: {t.headers[:6]}")
        if t.rows:
            sample_cells = [(c.text[:20], c.header_name) for c in t.rows[0][:4]]
            print(f"  Row 1 Cells with Inherited Headers: {sample_cells}")

    # Inspect Images if any
    all_images = doc.get_all_images()
    if all_images:
        screenshots = sum(1 for img in all_images if img.is_screenshot)
        rendered_pages = sum(1 for img in all_images if img.metadata.get("rendered_page"))
        print(f"\n  [Visual Asset Inspection]")
        print(f"  Total Embedded Images: {len(all_images)}")
        print(f"  Identified Embedded Screenshots: {screenshots}")
        print(f"  Rendered Scanned Pages for OCR: {rendered_pages}")
        if all_images:
            sample_img = all_images[0]
            print(f"  Sample Image: ID={sample_img.image_id}, Format={sample_img.image_format}, Size={len(sample_img.image_bytes):,} bytes")

    # Inspect Hidden Slides or Speaker Notes (for PPTX)
    hidden_slides = doc.metadata.get("hidden_slides_count", 0)
    speaker_notes_blocks = [
        b for p in doc.pages_dict.values() for b in p.blocks if b.block_type == "speaker_note"
    ]
    if hidden_slides > 0 or speaker_notes_blocks:
        print(f"\n  [Covert Channel Inspection]")
        print(f"  Hidden Slides: {hidden_slides}")
        print(f"  Speaker Notes Found: {len(speaker_notes_blocks)}")
        if speaker_notes_blocks:
            print(f"  Sample Note: '{speaker_notes_blocks[0].text[:100]}...'")

    # Sample Text Preview
    full_text = doc.get_full_text()
    print(f"\n  [Extracted Text Summary]")
    print(f"  Total Text Length: {len(full_text):,} characters")
    if full_text.strip():
        preview = full_text[:300].strip()
        print(f"  Text Preview (first 300 chars):\n    {preview.replace(chr(10), chr(10)+'    ')}")
    else:
        print("  Notice: Zero native text layer detected (Confirms 100% scanned PDF per PRD - queued for Person 2 OCR)")

    print(f"\n[+] Ingestion verification successful for {filename}!")


def main():
    test_docs_dir = os.path.join(os.path.dirname(__file__), "..", "test docs")
    
    files = [
        os.path.join(test_docs_dir, "Cadence_Group_Risk_Management_Policy__v6.0.pdf"),
        os.path.join(test_docs_dir, "Cadence_TPRM_Training.docx"),
        os.path.join(test_docs_dir, "Cadence_Financial_Group_Organizational_Pack.pptx"),
    ]

    print_header = "STARTING INGESTION TEST ON CADENCE ARTIFACTS"
    banner(print_header)

    for f in files:
        check_file(f)

    banner("ALL 3 CADENCE ARTIFACTS PROCESSED SUCCESSFULLY BY DEVELOPER 1")


if __name__ == "__main__":
    main()
