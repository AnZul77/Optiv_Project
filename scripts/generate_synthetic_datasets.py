"""
Synthetic & Held-Out Dataset Generator
Person 5: Evaluation Benchmark, Adversarial Testing & UI Lead
Roadmap: Day 10 & Day 15 Frozen Synthetic & Held-Out Evaluation Suites

Generates multi-modal test documents (DOCX, PDF, PPTX) populated with
controlled, international PII entities and corresponding ground-truth JSON files.
Strictly separates data/synthetic/ and data/heldout/ to prevent evaluation data leakage.
"""

import os
import json
from pathlib import Path
import docx
from docx.shared import Inches, Pt, RGBColor
from pptx import Presentation
from pptx.util import Inches as PptInches, Pt as PptPt
import pymupdf as fitz


PROJECT_ROOT = Path(__file__).parent.parent
SYNTHETIC_DIR = PROJECT_ROOT / "data" / "synthetic"
HELDOUT_DIR = PROJECT_ROOT / "data" / "heldout"
GT_DIR = PROJECT_ROOT / "data" / "ground_truth"


def create_synthetic_docx():
    """Generates synthetic_employee_records.docx with tables and paragraphs."""
    doc = docx.Document()
    doc.add_heading("Global Technology Corp - Internal Personnel Audit", level=1)
    
    doc.add_paragraph(
        "CONFIDENTIAL AUDIT REPORT: This document contains employee personnel records, "
        "security classifications, and global identification numbers for regulatory verification."
    )
    
    # Narrative paragraph with PII
    p1 = doc.add_paragraph("Lead System Architect: ")
    p1.add_run("Alexander Wright").bold = True
    p1.add_run(" (Email: ")
    p1.add_run("alex.wright@globalcorp.net")
    p1.add_run(", SSN: ")
    p1.add_run("382-91-4029")
    p1.add_run(", Mobile: ")
    p1.add_run("+1-555-839-2019")
    p1.add_run("). Base Office: New York Facility.")
    
    # Table with column headers and cell entities
    table = doc.add_table(rows=1, cols=5)
    table.style = "Table Grid"
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = "Employee ID"
    hdr_cells[1].text = "Full Name"
    hdr_cells[2].text = "Corporate Email"
    hdr_cells[3].text = "National ID"
    hdr_cells[4].text = "Corporate Card"
    
    records = [
        ("EMP-84920", "Priya Sundaram", "priya.sundaram@globalcorp.net", "PAN: ABCDE5678Z", "4111222233334444"),
        ("EMP-91823", "Desmond Vance", "desmond.vance@globalcorp.net", "SSN: 821-49-1029", "5500000000000004"),
        ("EMP-73910", "Elena Petrovska", "elena.p@globalcorp.net", "Passport: P8921049", "378282246310005"),
        ("EMP-60291", "Sunita Mehta", "sunita.mehta@globalcorp.net", "Aadhaar: 4829 1048 2910", "4000123456789010"),
    ]
    
    for emp_id, name, email, nat_id, card in records:
        row_cells = table.add_row().cells
        row_cells[0].text = emp_id
        row_cells[1].text = name
        row_cells[2].text = email
        row_cells[3].text = nat_id
        row_cells[4].text = card
        
    doc.add_paragraph(
        "\nOperational Note: Due Diligence Questionnaire T1-2 v1 was reviewed and Result: Approved. "
        "Standard policy INC-2026-9481 applies to all regional data centers outside the United States."
    )
    
    out_path = SYNTHETIC_DIR / "synthetic_employee_records.docx"
    doc.save(str(out_path))
    print(f"[+] Created synthetic DOCX: {out_path}")
    
    # Save Ground Truth
    gt_data = {
        "document_id": "synthetic_employee_records",
        "filename": "synthetic_employee_records.docx",
        "description": "Synthetic multi-column personnel audit document with international IDs, emails, cards, and operational non-PII terms.",
        "ground_truth_entities": [
            {"type": "PERSON", "page": 1, "value_snippet": "Alexander Wright", "text_start": 0, "text_end": 0},
            {"type": "EMAIL", "page": 1, "value_snippet": "alex.wright@globalcorp.net", "text_start": 0, "text_end": 0},
            {"type": "SSN", "page": 1, "value_snippet": "382-91-4029", "text_start": 0, "text_end": 0},
            {"type": "PHONE", "page": 1, "value_snippet": "+1-555-839-2019", "text_start": 0, "text_end": 0},
            {"type": "EMPLOYEE_ID", "page": 1, "value_snippet": "EMP-84920", "text_start": 0, "text_end": 0},
            {"type": "PERSON", "page": 1, "value_snippet": "Priya Sundaram", "text_start": 0, "text_end": 0},
            {"type": "EMAIL", "page": 1, "value_snippet": "priya.sundaram@globalcorp.net", "text_start": 0, "text_end": 0},
            {"type": "PAN", "page": 1, "value_snippet": "ABCDE5678Z", "text_start": 0, "text_end": 0},
            {"type": "CARD", "page": 1, "value_snippet": "4111222233334444", "text_start": 0, "text_end": 0},
            {"type": "PERSON", "page": 1, "value_snippet": "Desmond Vance", "text_start": 0, "text_end": 0},
            {"type": "SSN", "page": 1, "value_snippet": "821-49-1029", "text_start": 0, "text_end": 0},
            {"type": "PERSON", "page": 1, "value_snippet": "Elena Petrovska", "text_start": 0, "text_end": 0},
            {"type": "PASSPORT", "page": 1, "value_snippet": "P8921049", "text_start": 0, "text_end": 0},
            {"type": "PERSON", "page": 1, "value_snippet": "Sunita Mehta", "text_start": 0, "text_end": 0},
            {"type": "AADHAAR", "page": 1, "value_snippet": "4829 1048 2910", "text_start": 0, "text_end": 0},
        ]
    }
    gt_file = GT_DIR / "synthetic_employee_records.json"
    with open(gt_file, "w", encoding="utf-8") as f:
        json.dump(gt_data, f, indent=2)


def create_synthetic_pdf():
    """Generates synthetic_financial_audit.pdf via PyMuPDF."""
    doc = fitz.open()
    
    # Page 1: Executive Overview
    p1 = doc.new_page(width=612, height=792)
    p1.insert_text((50, 70), "Global Financial Services - Wire Transfer Audit", fontsize=18)
    p1.insert_text((50, 110), "Audited Entity: Horizon Capital Advisors", fontsize=12)
    p1.insert_text((50, 130), "Policy Standard: GRP-POL-8492 applies across regional branches.", fontsize=11)
    p1.insert_text((50, 160), "Authorized Account Signer: Marcus Sterling", fontsize=12)
    p1.insert_text((50, 180), "Primary Business Email: marcus.sterling@horizon-cap.com", fontsize=12)
    p1.insert_text((50, 200), "Direct Secure Telephone: +1-555-492-8172", fontsize=12)
    p1.insert_text((50, 230), "Residential Address: 492 Oak Ridge Drive, Suite 200, Dallas, TX 75201", fontsize=12)

    # Page 2: Banking & Account Identifiers
    p2 = doc.new_page(width=612, height=792)
    p2.insert_text((50, 70), "Section 2: Wire Clearing Identifiers", fontsize=16)
    p2.insert_text((50, 110), "Director Name: Yasmin El-Katib", fontsize=12)
    p2.insert_text((50, 130), "Director Identification Number: DIR-09281", fontsize=12)
    p2.insert_text((50, 150), "Taxpayer PAN: BKTPA9921M", fontsize=12)
    p2.insert_text((50, 170), "Indian Clearing IFSC: HDFC0001829 with Account: 981273948192", fontsize=12)
    p2.insert_text((50, 190), "Individual SSN: 492-18-9201", fontsize=12)
    p2.insert_text((50, 210), "Date of Birth: 08/23/1982", fontsize=12)
    p2.insert_text((50, 240), "Status: Approved. Case Reference: INC-2026-8812.", fontsize=11)
    
    out_path = SYNTHETIC_DIR / "synthetic_financial_audit.pdf"
    doc.save(str(out_path))
    doc.close()
    print(f"[+] Created synthetic PDF: {out_path}")
    
    gt_data = {
        "document_id": "synthetic_financial_audit",
        "filename": "synthetic_financial_audit.pdf",
        "description": "Multi-page synthetic financial document with banking, PAN, IFSC, SSN, DOB, and addresses.",
        "ground_truth_entities": [
            {"type": "PERSON", "page": 1, "value_snippet": "Marcus Sterling", "text_start": 0, "text_end": 0},
            {"type": "EMAIL", "page": 1, "value_snippet": "marcus.sterling@horizon-cap.com", "text_start": 0, "text_end": 0},
            {"type": "PHONE", "page": 1, "value_snippet": "+1-555-492-8172", "text_start": 0, "text_end": 0},
            {"type": "ADDRESS", "page": 1, "value_snippet": "492 Oak Ridge Drive, Suite 200, Dallas, TX 75201", "text_start": 0, "text_end": 0},
            {"type": "PERSON", "page": 2, "value_snippet": "Yasmin El-Katib", "text_start": 0, "text_end": 0},
            {"type": "DIRECTOR_ID", "page": 2, "value_snippet": "DIR-09281", "text_start": 0, "text_end": 0},
            {"type": "PAN", "page": 2, "value_snippet": "BKTPA9921M", "text_start": 0, "text_end": 0},
            {"type": "IFSC", "page": 2, "value_snippet": "HDFC0001829", "text_start": 0, "text_end": 0},
            {"type": "BANK_ACCOUNT", "page": 2, "value_snippet": "981273948192", "text_start": 0, "text_end": 0},
            {"type": "SSN", "page": 2, "value_snippet": "492-18-9201", "text_start": 0, "text_end": 0},
            {"type": "DOB", "page": 2, "value_snippet": "08/23/1982", "text_start": 0, "text_end": 0},
        ]
    }
    gt_file = GT_DIR / "synthetic_financial_audit.json"
    with open(gt_file, "w", encoding="utf-8") as f:
        json.dump(gt_data, f, indent=2)


def create_synthetic_pptx():
    """Generates synthetic_org_review.pptx with slide hierarchy and notes."""
    prs = Presentation()
    
    # Slide 1: Title
    slide1 = prs.slides.add_slide(prs.slide_layouts[0])
    slide1.shapes.title.text = "Enterprise Architecture & Leadership"
    slide1.placeholders[1].text = "Quarterly Governance Review - Cadence Group"
    
    # Slide 2: Hierarchy card
    slide2 = prs.slides.add_slide(prs.slide_layouts[5])
    slide2.shapes.title.text = "Technology Risk Division"
    
    txBox = slide2.shapes.add_textbox(PptInches(1), PptInches(2), PptInches(6), PptInches(3))
    tf = txBox.text_frame
    p = tf.paragraphs[0]
    p.text = "Chief Information Security Officer: Bartholomew Nkemdirim"
    p2 = tf.add_paragraph()
    p2.text = "Email: bartholomew.n@cadence-group.org | Employee ID: EMP-10492"
    p3 = tf.add_paragraph()
    p3.text = "Committee: Vendor Risk Management Group (Governing Authority)"
    
    # Covert speaker note with PII
    notes_slide = slide2.notes_slide
    text_frame = notes_slide.notes_text_frame
    text_frame.text = "Internal note: Executive mobile phone is +1-555-912-3841 for emergency escalation."
    
    out_path = SYNTHETIC_DIR / "synthetic_org_review.pptx"
    prs.save(str(out_path))
    print(f"[+] Created synthetic PPTX: {out_path}")
    
    gt_data = {
        "document_id": "synthetic_org_review",
        "filename": "synthetic_org_review.pptx",
        "description": "Synthetic presentation containing executive hierarchy cards, employee IDs, and speaker note covert channels.",
        "ground_truth_entities": [
            {"type": "PERSON", "page": 2, "value_snippet": "Bartholomew Nkemdirim", "text_start": 0, "text_end": 0},
            {"type": "EMAIL", "page": 2, "value_snippet": "bartholomew.n@cadence-group.org", "text_start": 0, "text_end": 0},
            {"type": "EMPLOYEE_ID", "page": 2, "value_snippet": "EMP-10492", "text_start": 0, "text_end": 0},
            {"type": "PHONE", "page": 2, "value_snippet": "+1-555-912-3841", "text_start": 0, "text_end": 0},
        ]
    }
    gt_file = GT_DIR / "synthetic_org_review.json"
    with open(gt_file, "w", encoding="utf-8") as f:
        json.dump(gt_data, f, indent=2)


def create_heldout_dataset():
    """Generates strictly separated frozen held-out test suite."""
    # Heldout DOCX: Third-Party Risk Assessment
    doc = docx.Document()
    doc.add_heading("Third-Party Vendor Assessment - Frozen Test Set", level=1)
    doc.add_paragraph("Held-Out Validation Document: Untuned benchmark artifact.")
    
    p = doc.add_paragraph("Primary Vendor Security Officer: ")
    p.add_run("Kavita Ramanathan").bold = True
    p.add_run(" (Email: ")
    p.add_run("kavita.ramanathan@clouddefense.com")
    p.add_run(", SSN: ")
    p.add_run("194-82-9481")
    p.add_run(", Phone: ")
    p.add_run("+1-555-302-9481")
    p.add_run("). Direct National Tax ID: ")
    p.add_run("PAN: AXPPR9481K")
    p.add_run(".")
    
    doc.add_paragraph(
        "Verification: Template Due Diligence Questionnaire T1-2 v1 completed. "
        "Status: Approved by Information Security Committee."
    )
    
    heldout_docx = HELDOUT_DIR / "heldout_vendor_assessment.docx"
    doc.save(str(heldout_docx))
    print(f"[+] Created frozen held-out DOCX: {heldout_docx}")

    # Heldout PDF: Healthcare & Benefits Statement
    pdf_doc = fitz.open()
    page = pdf_doc.new_page(width=612, height=792)
    page.insert_text((50, 70), "Employee Benefits & Beneficiary Designation (Held-Out)", fontsize=16)
    page.insert_text((50, 110), "Employee Name: Gabriel O'Connor", fontsize=12)
    page.insert_text((50, 130), "Corporate ID: EMP-55829", fontsize=12)
    page.insert_text((50, 150), "SSN: 729-10-4829", fontsize=12)
    page.insert_text((50, 170), "Date of Birth: 05/19/1990", fontsize=12)
    page.insert_text((50, 190), "Passport Number: K9182374", fontsize=12)
    page.insert_text((50, 210), "Contact Email: gabriel.oc@securecorp.net", fontsize=12)
    page.insert_text((50, 230), "Home Address: 742 Evergreen Terrace, Springfield, OR 97477", fontsize=12)
    page.insert_text((50, 260), "Control Identifier: CTL-IAM-4029. Result: Approved.", fontsize=11)
    
    heldout_pdf = HELDOUT_DIR / "heldout_benefits_statement.pdf"
    pdf_doc.save(str(heldout_pdf))
    pdf_doc.close()
    print(f"[+] Created frozen held-out PDF: {heldout_pdf}")

    # Ground truth for held-out evaluation
    heldout_gt = [
        {
            "document_id": "heldout_vendor_assessment",
            "filename": "heldout_vendor_assessment.docx",
            "description": "Frozen held-out vendor assessment with zero parameter tuning.",
            "ground_truth_entities": [
                {"type": "PERSON", "page": 1, "value_snippet": "Kavita Ramanathan", "text_start": 0, "text_end": 0},
                {"type": "EMAIL", "page": 1, "value_snippet": "kavita.ramanathan@clouddefense.com", "text_start": 0, "text_end": 0},
                {"type": "SSN", "page": 1, "value_snippet": "194-82-9481", "text_start": 0, "text_end": 0},
                {"type": "PHONE", "page": 1, "value_snippet": "+1-555-302-9481", "text_start": 0, "text_end": 0},
                {"type": "PAN", "page": 1, "value_snippet": "AXPPR9481K", "text_start": 0, "text_end": 0},
            ]
        },
        {
            "document_id": "heldout_benefits_statement",
            "filename": "heldout_benefits_statement.pdf",
            "description": "Frozen held-out benefits statement with zero parameter tuning.",
            "ground_truth_entities": [
                {"type": "PERSON", "page": 1, "value_snippet": "Gabriel O'Connor", "text_start": 0, "text_end": 0},
                {"type": "EMPLOYEE_ID", "page": 1, "value_snippet": "EMP-55829", "text_start": 0, "text_end": 0},
                {"type": "SSN", "page": 1, "value_snippet": "729-10-4829", "text_start": 0, "text_end": 0},
                {"type": "DOB", "page": 1, "value_snippet": "05/19/1990", "text_start": 0, "text_end": 0},
                {"type": "PASSPORT", "page": 1, "value_snippet": "K9182374", "text_start": 0, "text_end": 0},
                {"type": "EMAIL", "page": 1, "value_snippet": "gabriel.oc@securecorp.net", "text_start": 0, "text_end": 0},
                {"type": "ADDRESS", "page": 1, "value_snippet": "742 Evergreen Terrace, Springfield, OR 97477", "text_start": 0, "text_end": 0},
            ]
        }
    ]

    for rec in heldout_gt:
        file_path = HELDOUT_DIR / f"{rec['document_id']}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2)
        # Also store in GT_DIR for automated discovery
        with open(GT_DIR / f"{rec['document_id']}.json", "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2)


def main():
    SYNTHETIC_DIR.mkdir(parents=True, exist_ok=True)
    HELDOUT_DIR.mkdir(parents=True, exist_ok=True)
    GT_DIR.mkdir(parents=True, exist_ok=True)
    
    print("=" * 60)
    print("  GENERATING SYNTHETIC & HELDOUT BENCHMARK DATASETS")
    print("=" * 60)
    
    create_synthetic_docx()
    create_synthetic_pdf()
    create_synthetic_pptx()
    create_heldout_dataset()
    
    print("\n[+] All synthetic and held-out benchmark datasets successfully generated!")


if __name__ == "__main__":
    main()
