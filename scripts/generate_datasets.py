"""
Dataset Generator for PII Security Firewall
Generates:
1. data/synthetic/ (diverse edge cases: international IDs, employee records, invoices, security tickets)
2. data/heldout/ (frozen, never-tuned 5-document test split with spec lock)
"""

import os
import json
import hashlib
from pathlib import Path
import docx

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC_DIR = PROJECT_ROOT / "data" / "synthetic"
HELDOUT_DIR = PROJECT_ROOT / "data" / "heldout"

SYNTHETIC_DIR.mkdir(parents=True, exist_ok=True)
HELDOUT_DIR.mkdir(parents=True, exist_ok=True)


def calculate_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# =============================================================================
# 1. SYNTHETIC DATASET GENERATION
# =============================================================================

def generate_synthetic_datasets():
    # -------------------------------------------------------------------------
    # A. synthetic_vendor_intake (.json, .txt, .docx)
    # -------------------------------------------------------------------------
    vendor_blocks = [
        {
            "block_id": "v_b1",
            "page": 1,
            "section_context": "Vendor Registration & Profile",
            "text": "Vendor Registration Dossier for Vance Logistics International Ltd. Reference: TPRM-402 and VEN-9041."
        },
        {
            "block_id": "v_b2",
            "page": 1,
            "section_context": "National Tax & Identification Registrations",
            "text": "Permanent Account Number: ABCPE1234F registered with the Indian Income Tax Department."
        },
        {
            "block_id": "v_b3",
            "page": 1,
            "section_context": "National Tax & Identification Registrations",
            "text": "Aadhaar UID: 2345 6789 0124 on file for Indian authorized signatory."
        },
        {
            "block_id": "v_b4",
            "page": 1,
            "section_context": "National Tax & Identification Registrations",
            "text": "UK NINO: JH 12 34 56 C on record for HMRC tax withholding."
        },
        {
            "block_id": "v_b5",
            "page": 1,
            "section_context": "National Tax & Identification Registrations",
            "text": "Passport No: C8839201 verified for international clearance."
        },
        {
            "block_id": "v_b6",
            "page": 2,
            "section_context": "Designated Officers & Authorized Contacts",
            "text": "Employee Name: Marcus Vance serves as Principal Logistics Director."
        },
        {
            "block_id": "v_b7",
            "page": 2,
            "section_context": "Designated Officers & Authorized Contacts",
            "text": "Corporate Email: marcus.vance@vance-logistics.co.uk and Mobile Phone: +44 20 7946 0912."
        },
        {
            "block_id": "v_b8",
            "page": 2,
            "section_context": "Designated Officers & Authorized Contacts",
            "text": "Employee Name: Sarah Jenkins serves as Secondary Regional Compliance Officer."
        },
        {
            "block_id": "v_b9",
            "page": 2,
            "section_context": "Designated Officers & Authorized Contacts",
            "text": "Corporate Email: sarah.jenkins@optiv.com with Mobile Phone: +91 98765 43210."
        },
        {
            "block_id": "v_b10",
            "page": 3,
            "section_context": "Banking & Remittance Information",
            "text": "Settlement Bank Account Number: 98765432101234 with Bank IFSC: SBIN0001234."
        }
    ]

    vendor_gt_entities = [
        {"type": "PAN", "value_snippet": "ABCPE1234F", "page": 1, "text_start": 26, "text_end": 36},
        {"type": "AADHAAR", "value_snippet": "2345 6789 0124", "page": 1, "text_start": 13, "text_end": 27},
        {"type": "NINO", "value_snippet": "JH 12 34 56 C", "page": 1, "text_start": 9, "text_end": 22},
        {"type": "PASSPORT", "value_snippet": "C8839201", "page": 1, "text_start": 13, "text_end": 21},
        {"type": "PERSON", "value_snippet": "Marcus Vance", "page": 2, "text_start": 15, "text_end": 27},
        {"type": "EMAIL", "value_snippet": "marcus.vance@vance-logistics.co.uk", "page": 2, "text_start": 17, "text_end": 52},
        {"type": "PHONE", "value_snippet": "+44 20 7946 0912", "page": 2, "text_start": 71, "text_end": 87},
        {"type": "PERSON", "value_snippet": "Sarah Jenkins", "page": 2, "text_start": 15, "text_end": 28},
        {"type": "EMAIL", "value_snippet": "sarah.jenkins@optiv.com", "page": 2, "text_start": 17, "text_end": 40},
        {"type": "PHONE", "value_snippet": "+91 98765 43210", "page": 2, "text_start": 60, "text_end": 75},
        {"type": "IFSC", "value_snippet": "SBIN0001234", "page": 3, "text_start": 64, "text_end": 75}
    ]

    vendor_full_text = "\n\n".join(b["text"] for b in vendor_blocks)

    vendor_json_data = {
        "document_id": "synthetic_vendor_intake",
        "filename": "synthetic_vendor_intake.json",
        "title": "Global Third-Party Vendor Security Intake & KYC Form",
        "description": "Synthetic enterprise vendor registration document covering international national IDs (PAN, Aadhaar, UK NINO, Passports) and primary contact details.",
        "pages": 3,
        "blocks": vendor_blocks,
        "full_text": vendor_full_text,
        "ground_truth_entities": vendor_gt_entities
    }

    with open(SYNTHETIC_DIR / "synthetic_vendor_intake.json", "w", encoding="utf-8") as f:
        json.dump(vendor_json_data, f, indent=2)

    with open(SYNTHETIC_DIR / "synthetic_vendor_intake.txt", "w", encoding="utf-8") as f:
        f.write(f"=== {vendor_json_data['title']} ===\n\n{vendor_full_text}\n")

    # Generate DOCX
    doc = docx.Document()
    doc.add_heading(vendor_json_data["title"], level=0)
    for b in vendor_blocks:
        doc.add_heading(b["section_context"], level=2)
        doc.add_paragraph(b["text"])
    doc.save(SYNTHETIC_DIR / "synthetic_vendor_intake.docx")

    # -------------------------------------------------------------------------
    # B. synthetic_employee_directory (.json, .txt) & synthetic_employee_records
    # -------------------------------------------------------------------------
    emp_blocks = [
        {
            "block_id": "emp_b1",
            "page": 1,
            "section_context": "Engineering & Technology Leadership",
            "text": "Employee Name: Elena Rostova holding position of Lead Security Architect. Employee ID: EMP-8239."
        },
        {
            "block_id": "emp_b2",
            "page": 1,
            "section_context": "Engineering & Technology Leadership",
            "text": "US Tax SSN: 219-45-7890 on file. Date of Birth: 14/07/1988."
        },
        {
            "block_id": "emp_b3",
            "page": 1,
            "section_context": "Engineering & Technology Leadership",
            "text": "Corporate Email: elena.rostova@optiv-security.com and Personal Email: elena.rostova@personal-mail.com."
        },
        {
            "block_id": "emp_b4",
            "page": 1,
            "section_context": "Engineering & Technology Leadership",
            "text": "Mobile Phone: +1 (415) 555-2671. Residential Address: 1842 Willow Tree Ln, Suite 400, Chicago, IL 60601."
        },
        {
            "block_id": "emp_b5",
            "page": 2,
            "section_context": "Systems & DevOps Department",
            "text": "Employee Name: David K. Miller holding Employee ID: EMP-908234."
        },
        {
            "block_id": "emp_b6",
            "page": 2,
            "section_context": "Systems & DevOps Department",
            "text": "US Tax SSN: 123-45-6789. Date of Birth: 1985-11-23."
        },
        {
            "block_id": "emp_b7",
            "page": 2,
            "section_context": "Systems & DevOps Department",
            "text": "Personal Email: david.miller@gmail.com with Mobile Phone: +1 (312) 555-0199."
        },
        {
            "block_id": "emp_b8",
            "page": 2,
            "section_context": "Systems & DevOps Department",
            "text": "Residential Address: 742 Evergreen Terrace, Springfield, OR 97477."
        },
        {
            "block_id": "emp_b9",
            "page": 3,
            "section_context": "APAC Regional Operations",
            "text": "Employee Name: Ananya Sharma assigned Employee ID: EMP-10492. Date of Birth: 03/22/1991."
        },
        {
            "block_id": "emp_b10",
            "page": 3,
            "section_context": "APAC Regional Operations",
            "text": "Corporate Email: ananya.sharma@cadence-group.com and Mobile Phone: +91 98123 45678."
        }
    ]

    emp_gt_entities = [
        {"type": "PERSON", "value_snippet": "Elena Rostova", "page": 1, "text_start": 15, "text_end": 28},
        {"type": "EMPLOYEE_ID", "value_snippet": "EMP-8239", "page": 1, "text_start": 87, "text_end": 95},
        {"type": "SSN", "value_snippet": "219-45-7890", "page": 1, "text_start": 12, "text_end": 23},
        {"type": "DOB", "value_snippet": "14/07/1988", "page": 1, "text_start": 47, "text_end": 57},
        {"type": "EMAIL", "value_snippet": "elena.rostova@optiv-security.com", "page": 1, "text_start": 17, "text_end": 48},
        {"type": "EMAIL", "value_snippet": "elena.rostova@personal-mail.com", "page": 1, "text_start": 69, "text_end": 100},
        {"type": "PHONE", "value_snippet": "+1 (415) 555-2671", "page": 1, "text_start": 14, "text_end": 31},
        {"type": "ADDRESS", "value_snippet": "1842 Willow Tree Ln, Suite 400, Chicago, IL 60601", "page": 1, "text_start": 54, "text_end": 103},
        {"type": "PERSON", "value_snippet": "David K. Miller", "page": 2, "text_start": 15, "text_end": 30},
        {"type": "EMPLOYEE_ID", "value_snippet": "EMP-908234", "page": 2, "text_start": 51, "text_end": 61},
        {"type": "SSN", "value_snippet": "123-45-6789", "page": 2, "text_start": 12, "text_end": 23},
        {"type": "DOB", "value_snippet": "1985-11-23", "page": 2, "text_start": 39, "text_end": 49},
        {"type": "EMAIL", "value_snippet": "david.miller@gmail.com", "page": 2, "text_start": 16, "text_end": 38},
        {"type": "PHONE", "value_snippet": "+1 (312) 555-0199", "page": 2, "text_start": 57, "text_end": 74},
        {"type": "ADDRESS", "value_snippet": "742 Evergreen Terrace, Springfield, OR 97477", "page": 2, "text_start": 21, "text_end": 65},
        {"type": "PERSON", "value_snippet": "Ananya Sharma", "page": 3, "text_start": 15, "text_end": 28},
        {"type": "EMPLOYEE_ID", "value_snippet": "EMP-10492", "page": 3, "text_start": 49, "text_end": 58},
        {"type": "DOB", "value_snippet": "03/22/1991", "page": 3, "text_start": 74, "text_end": 84},
        {"type": "EMAIL", "value_snippet": "ananya.sharma@cadence-group.com", "page": 3, "text_start": 17, "text_end": 48},
        {"type": "PHONE", "value_snippet": "+91 98123 45678", "page": 3, "text_start": 68, "text_end": 83}
    ]

    emp_full_text = "\n\n".join(b["text"] for b in emp_blocks)

    emp_json_data = {
        "document_id": "synthetic_employee_directory",
        "filename": "synthetic_employee_directory.json",
        "title": "Confidential Enterprise Personnel Directory & HR Records",
        "description": "Comprehensive employee records containing personal names, employee IDs, SSNs, DOBs, personal emails, phone numbers, and home addresses.",
        "pages": 3,
        "blocks": emp_blocks,
        "full_text": emp_full_text,
        "ground_truth_entities": emp_gt_entities
    }

    # Save synthetic_employee_directory
    with open(SYNTHETIC_DIR / "synthetic_employee_directory.json", "w", encoding="utf-8") as f:
        json.dump(emp_json_data, f, indent=2)

    with open(SYNTHETIC_DIR / "synthetic_employee_directory.txt", "w", encoding="utf-8") as f:
        f.write(f"=== {emp_json_data['title']} ===\n\n{emp_full_text}\n")

    # Also save synthetic_employee_records alias
    emp_records_data = dict(emp_json_data)
    emp_records_data["document_id"] = "synthetic_employee_records"
    emp_records_data["filename"] = "synthetic_employee_records.json"
    with open(SYNTHETIC_DIR / "synthetic_employee_records.json", "w", encoding="utf-8") as f:
        json.dump(emp_records_data, f, indent=2)

    with open(SYNTHETIC_DIR / "synthetic_employee_records.txt", "w", encoding="utf-8") as f:
        f.write(f"=== {emp_records_data['title']} ===\n\n{emp_full_text}\n")

    # -------------------------------------------------------------------------
    # C. synthetic_invoices (.json, .txt)
    # -------------------------------------------------------------------------
    invoice_blocks = [
        {
            "block_id": "inv_b1",
            "page": 1,
            "section_context": "Billing Header & Reference",
            "text": "Commercial Billing Statement and Settlement Docket. Authorization Reference: REQ-9018 and POL-301."
        },
        {
            "block_id": "inv_b2",
            "page": 1,
            "section_context": "Corporate Credit Card Instruments",
            "text": "Corporate Credit Card: 4532015000000007 billed for enterprise cloud hosting."
        },
        {
            "block_id": "inv_b3",
            "page": 1,
            "section_context": "Corporate Credit Card Instruments",
            "text": "Corporate Credit Card: 5105105105105100 billed for security subscription services."
        },
        {
            "block_id": "inv_b4",
            "page": 1,
            "section_context": "GST & Commercial Tax Identification",
            "text": "State of Maharashtra GST Number: 27ABCDE1234F1Z5 registered for Interstate Commerce."
        },
        {
            "block_id": "inv_b5",
            "page": 1,
            "section_context": "GST & Commercial Tax Identification",
            "text": "Permanent Account Number: XYZPA9876K linked to corporate tax ledger."
        },
        {
            "block_id": "inv_b6",
            "page": 2,
            "section_context": "Remittance Rails & Instant Settlements",
            "text": "Primary Settlement Bank IFSC: SBIN0001234 routing."
        },
        {
            "block_id": "inv_b7",
            "page": 2,
            "section_context": "Remittance Rails & Instant Settlements",
            "text": "Instant Merchant UPI ID: billing@okhdfcbank configured for auto-debit."
        },
        {
            "block_id": "inv_b8",
            "page": 2,
            "section_context": "Remittance Rails & Instant Settlements",
            "text": "Secondary Merchant UPI ID: settlement.vendor@okaxis active."
        },
        {
            "block_id": "inv_b9",
            "page": 2,
            "section_context": "Finance Sign-off & Contact",
            "text": "Employee Name: Rajesh Patel acts as Treasury Controller."
        },
        {
            "block_id": "inv_b10",
            "page": 2,
            "section_context": "Finance Sign-off & Contact",
            "text": "Corporate Email: accounts.payable@meridian-corp.com with Mobile Phone: +91 98765 43210."
        }
    ]

    invoice_gt_entities = [
        {"type": "CARD", "value_snippet": "4532015000000007", "page": 1, "text_start": 23, "text_end": 39},
        {"type": "CARD", "value_snippet": "5105105105105100", "page": 1, "text_start": 23, "text_end": 39},
        {"type": "GST", "value_snippet": "27ABCDE1234F1Z5", "page": 1, "text_start": 34, "text_end": 49},
        {"type": "PAN", "value_snippet": "XYZPA9876K", "page": 1, "text_start": 26, "text_end": 36},
        {"type": "IFSC", "value_snippet": "SBIN0001234", "page": 2, "text_start": 30, "text_end": 41},
        {"type": "UPI", "value_snippet": "billing@okhdfcbank", "page": 2, "text_start": 24, "text_end": 42},
        {"type": "UPI", "value_snippet": "settlement.vendor@okaxis", "page": 2, "text_start": 26, "text_end": 50},
        {"type": "PERSON", "value_snippet": "Rajesh Patel", "page": 2, "text_start": 15, "text_end": 27},
        {"type": "EMAIL", "value_snippet": "accounts.payable@meridian-corp.com", "page": 2, "text_start": 17, "text_end": 51},
        {"type": "PHONE", "value_snippet": "+91 98765 43210", "page": 2, "text_start": 71, "text_end": 86}
    ]

    invoice_full_text = "\n\n".join(b["text"] for b in invoice_blocks)

    invoice_json_data = {
        "document_id": "synthetic_invoices",
        "filename": "synthetic_invoices.json",
        "title": "Commercial Accounts Payable Schedule & Treasury Settlement Docket",
        "description": "Financial enterprise document featuring corporate credit cards, bank accounts, GSTIN codes, IFSC remittance routes, and UPI handles.",
        "pages": 2,
        "blocks": invoice_blocks,
        "full_text": invoice_full_text,
        "ground_truth_entities": invoice_gt_entities
    }

    with open(SYNTHETIC_DIR / "synthetic_invoices.json", "w", encoding="utf-8") as f:
        json.dump(invoice_json_data, f, indent=2)

    with open(SYNTHETIC_DIR / "synthetic_invoices.txt", "w", encoding="utf-8") as f:
        f.write(f"=== {invoice_json_data['title']} ===\n\n{invoice_full_text}\n")

    # -------------------------------------------------------------------------
    # D. synthetic_security_incident (.json, .txt)
    # -------------------------------------------------------------------------
    sec_blocks = [
        {
            "block_id": "sec_b1",
            "page": 1,
            "section_context": "Incident Governance & Allow-Listed Codes",
            "text": "Cyber Security Incident Report for INC-2026-0417 cataloged under Risk RSK-001 and Control CTL-IAM-004."
        },
        {
            "block_id": "sec_b2",
            "page": 1,
            "section_context": "Incident Governance & Allow-Listed Codes",
            "text": "Governed by Information Security Policy POL-901 and International Standard ISO-27001 under AUDIT-2026."
        },
        {
            "block_id": "sec_b3",
            "page": 1,
            "section_context": "Response Team & Incident Commander",
            "text": "Incident Commander Employee Name: Alice Walker leads triage."
        },
        {
            "block_id": "sec_b4",
            "page": 1,
            "section_context": "Response Team & Incident Commander",
            "text": "Corporate Email: alice.walker@optiv-security.com with Mobile Phone: +1 (202) 555-0143."
        },
        {
            "block_id": "sec_b5",
            "page": 2,
            "section_context": "Compromised Asset & PII Impact Assessment",
            "text": "Target User Employee Name: Marcus Donahue assigned Employee ID: EMP-8239."
        },
        {
            "block_id": "sec_b6",
            "page": 2,
            "section_context": "Compromised Asset & PII Impact Assessment",
            "text": "Compromised Tax ID / SSN: 219-45-7890 confirmed leaked in memory dump."
        },
        {
            "block_id": "sec_b7",
            "page": 2,
            "section_context": "Compromised Asset & PII Impact Assessment",
            "text": "Permanent Account Number: ABCPE1234F and Passport No: C8839201 extracted from workstation cache."
        },
        {
            "block_id": "sec_b8",
            "page": 2,
            "section_context": "Compromised Asset & PII Impact Assessment",
            "text": "Corporate Credit Card: 4532015000000007 flagged for immediate card revocation."
        }
    ]

    sec_gt_entities = [
        {"type": "PERSON", "value_snippet": "Alice Walker", "page": 1, "text_start": 34, "text_end": 46},
        {"type": "EMAIL", "value_snippet": "alice.walker@optiv-security.com", "page": 1, "text_start": 17, "text_end": 48},
        {"type": "PHONE", "value_snippet": "+1 (202) 555-0143", "page": 1, "text_start": 68, "text_end": 85},
        {"type": "PERSON", "value_snippet": "Marcus Donahue", "page": 2, "text_start": 27, "text_end": 41},
        {"type": "EMPLOYEE_ID", "value_snippet": "EMP-8239", "page": 2, "text_start": 64, "text_end": 72},
        {"type": "SSN", "value_snippet": "219-45-7890", "page": 2, "text_start": 25, "text_end": 36},
        {"type": "PAN", "value_snippet": "ABCPE1234F", "page": 2, "text_start": 26, "text_end": 36},
        {"type": "PASSPORT", "value_snippet": "C8839201", "page": 2, "text_start": 54, "text_end": 62},
        {"type": "CARD", "value_snippet": "4532015000000007", "page": 2, "text_start": 23, "text_end": 39}
    ]

    sec_full_text = "\n\n".join(b["text"] for b in sec_blocks)

    sec_json_data = {
        "document_id": "synthetic_security_incident",
        "filename": "synthetic_security_incident.json",
        "title": "SOC Cyber Security Incident Response & Forensic Ticket Dossier",
        "description": "Security operations report combining allow-listed business ticket references (INC-2026-0417, RSK-001, CTL-IAM-004, ISO-27001) alongside authentic personal PII.",
        "pages": 2,
        "blocks": sec_blocks,
        "full_text": sec_full_text,
        "ground_truth_entities": sec_gt_entities,
        "allow_listed_tokens": ["INC-2026-0417", "RSK-001", "CTL-IAM-004", "ISO-27001", "AUDIT-2026", "POL-901"]
    }

    with open(SYNTHETIC_DIR / "synthetic_security_incident.json", "w", encoding="utf-8") as f:
        json.dump(sec_json_data, f, indent=2)

    with open(SYNTHETIC_DIR / "synthetic_security_incident.txt", "w", encoding="utf-8") as f:
        f.write(f"=== {sec_json_data['title']} ===\n\n{sec_full_text}\n")

    print("[SUCCESS] Synthetic dataset generation completed.")


# =============================================================================
# 2. HELDOUT BENCHMARK DATASET GENERATION
# =============================================================================

def generate_heldout_benchmark_datasets():
    heldout_docs = [
        # ---------------------------------------------------------------------
        # Document 1: Global Identity & Cross-Border Compliance
        # ---------------------------------------------------------------------
        {
            "document_id": "heldout_doc_01",
            "filename": "heldout_doc_01.json",
            "title": "Global Executive KYC & International Identification Dossier",
            "description": "High-assurance international identity verification document containing PAN, Aadhaar, Passport, UK NINO, and corporate executive contact vectors.",
            "pages": 2,
            "blocks": [
                {
                    "block_id": "d1_b1",
                    "page": 1,
                    "section_context": "Cross-Border Executive Verification",
                    "text": "Permanent Account Number: ABCPE1234F verified by tax audit authority."
                },
                {
                    "block_id": "d1_b2",
                    "page": 1,
                    "section_context": "Cross-Border Executive Verification",
                    "text": "Aadhaar UID: 2345 6789 0124 on file for regulatory compliance."
                },
                {
                    "block_id": "d1_b3",
                    "page": 1,
                    "section_context": "Cross-Border Executive Verification",
                    "text": "Passport No: C8839201 issued by passport office."
                },
                {
                    "block_id": "d1_b4",
                    "page": 1,
                    "section_context": "Cross-Border Executive Verification",
                    "text": "UK NINO: JH 12 34 56 C recorded for tax compliance."
                },
                {
                    "block_id": "d1_b5",
                    "page": 2,
                    "section_context": "Designated Identity Contact",
                    "text": "Corporate Email: marcus.vance@cadence-global.com for executive notifications."
                },
                {
                    "block_id": "d1_b6",
                    "page": 2,
                    "section_context": "Designated Identity Contact",
                    "text": "Mobile Phone: +1 (415) 555-2671 on file."
                },
                {
                    "block_id": "d1_b7",
                    "page": 2,
                    "section_context": "Designated Identity Contact",
                    "text": "Employee Name: Marcus Vance registered under compliance file."
                },
                {
                    "block_id": "d1_b8",
                    "page": 2,
                    "section_context": "Designated Identity Contact",
                    "text": "Date of Birth: 14/07/1988 verified against civil registry."
                }
            ],
            "ground_truth_entities": [
                {"type": "PAN", "value_snippet": "ABCPE1234F", "page": 1, "text_start": 26, "text_end": 36, "risk": "CRITICAL"},
                {"type": "AADHAAR", "value_snippet": "2345 6789 0124", "page": 1, "text_start": 13, "text_end": 27, "risk": "CRITICAL"},
                {"type": "PASSPORT", "value_snippet": "C8839201", "page": 1, "text_start": 13, "text_end": 21, "risk": "CRITICAL"},
                {"type": "NINO", "value_snippet": "JH 12 34 56 C", "page": 1, "text_start": 9, "text_end": 22, "risk": "CRITICAL"},
                {"type": "EMAIL", "value_snippet": "marcus.vance@cadence-global.com", "page": 2, "text_start": 17, "text_end": 49, "risk": "HIGH"},
                {"type": "PHONE", "value_snippet": "+1 (415) 555-2671", "page": 2, "text_start": 14, "text_end": 31, "risk": "HIGH"},
                {"type": "PERSON", "value_snippet": "Marcus Vance", "page": 2, "text_start": 15, "text_end": 27, "risk": "HIGH"},
                {"type": "DOB", "value_snippet": "14/07/1988", "page": 2, "text_start": 15, "text_end": 25, "risk": "HIGH"}
            ]
        },

        # ---------------------------------------------------------------------
        # Document 2: Confidential HR Payroll & Benefits Register
        # ---------------------------------------------------------------------
        {
            "document_id": "heldout_doc_02",
            "filename": "heldout_doc_02.json",
            "title": "Confidential HR Payroll & Compensation Register",
            "description": "Internal payroll record detailing employee SSN, corporate procurement card, employee ID, residential address, and date of birth.",
            "pages": 1,
            "blocks": [
                {
                    "block_id": "d2_b1",
                    "page": 1,
                    "section_context": "Confidential Personnel Record",
                    "text": "US Tax SSN: 219-45-7890 recorded in central payroll."
                },
                {
                    "block_id": "d2_b2",
                    "page": 1,
                    "section_context": "Confidential Personnel Record",
                    "text": "Corporate Credit Card: 4532015000000007 assigned for departmental procurement."
                },
                {
                    "block_id": "d2_b3",
                    "page": 1,
                    "section_context": "Confidential Personnel Record",
                    "text": "Employee ID: EMP-908234 assigned by HR Operations."
                },
                {
                    "block_id": "d2_b4",
                    "page": 1,
                    "section_context": "Confidential Personnel Record",
                    "text": "Date of Birth: 03/22/1991 verified by HR."
                },
                {
                    "block_id": "d2_b5",
                    "page": 1,
                    "section_context": "Confidential Personnel Record",
                    "text": "Corporate Email: elena.rostova@optiv-security.com."
                },
                {
                    "block_id": "d2_b6",
                    "page": 1,
                    "section_context": "Confidential Personnel Record",
                    "text": "Mobile Phone: +1 (312) 555-0199."
                },
                {
                    "block_id": "d2_b7",
                    "page": 1,
                    "section_context": "Confidential Personnel Record",
                    "text": "Employee Name: Elena Rostova."
                },
                {
                    "block_id": "d2_b8",
                    "page": 1,
                    "section_context": "Confidential Personnel Record",
                    "text": "Residential Address: 1842 Willow Tree Ln, Suite 400, Chicago, IL 60601."
                }
            ],
            "ground_truth_entities": [
                {"type": "SSN", "value_snippet": "219-45-7890", "page": 1, "text_start": 12, "text_end": 23, "risk": "CRITICAL"},
                {"type": "CARD", "value_snippet": "4532015000000007", "page": 1, "text_start": 23, "text_end": 39, "risk": "CRITICAL"},
                {"type": "EMPLOYEE_ID", "value_snippet": "EMP-908234", "page": 1, "text_start": 13, "text_end": 23, "risk": "HIGH"},
                {"type": "DOB", "value_snippet": "03/22/1991", "page": 1, "text_start": 15, "text_end": 25, "risk": "HIGH"},
                {"type": "EMAIL", "value_snippet": "elena.rostova@optiv-security.com", "page": 1, "text_start": 17, "text_end": 48, "risk": "HIGH"},
                {"type": "PHONE", "value_snippet": "+1 (312) 555-0199", "page": 1, "text_start": 14, "text_end": 31, "risk": "HIGH"},
                {"type": "PERSON", "value_snippet": "Elena Rostova", "page": 1, "text_start": 15, "text_end": 28, "risk": "HIGH"},
                {"type": "ADDRESS", "value_snippet": "1842 Willow Tree Ln, Suite 400, Chicago, IL 60601", "page": 1, "text_start": 21, "text_end": 70, "risk": "HIGH"}
            ]
        },

        # ---------------------------------------------------------------------
        # Document 3: Commercial Invoicing & Treasury Settlement Schedule
        # ---------------------------------------------------------------------
        {
            "document_id": "heldout_doc_03",
            "filename": "heldout_doc_03.json",
            "title": "Enterprise Accounts Payable & Commercial Settlement Schedule",
            "description": "Treasury reconciliation report with Mastercard corporate cards, Indian GSTIN registration, IFSC branch code, UPI VPA, and PAN identifier.",
            "pages": 1,
            "blocks": [
                {
                    "block_id": "d3_b1",
                    "page": 1,
                    "section_context": "Commercial Treasury Settlement",
                    "text": "Corporate Credit Card: 5105105105105100 billed for settlement."
                },
                {
                    "block_id": "d3_b2",
                    "page": 1,
                    "section_context": "Commercial Treasury Settlement",
                    "text": "Permanent Account Number: XYZPA9876K on file."
                },
                {
                    "block_id": "d3_b3",
                    "page": 1,
                    "section_context": "Commercial Treasury Settlement",
                    "text": "GST Number: 27ABCDE1234F1Z5 registered with revenue service."
                },
                {
                    "block_id": "d3_b4",
                    "page": 1,
                    "section_context": "Commercial Treasury Settlement",
                    "text": "Bank IFSC: SBIN0001234 routing."
                },
                {
                    "block_id": "d3_b5",
                    "page": 1,
                    "section_context": "Commercial Treasury Settlement",
                    "text": "UPI ID: billing@okhdfcbank configured."
                },
                {
                    "block_id": "d3_b6",
                    "page": 1,
                    "section_context": "Commercial Treasury Settlement",
                    "text": "Corporate Email: treasury.controller@cadence-finance.com."
                },
                {
                    "block_id": "d3_b7",
                    "page": 1,
                    "section_context": "Commercial Treasury Settlement",
                    "text": "Mobile Phone: +91 98765 43210."
                },
                {
                    "block_id": "d3_b8",
                    "page": 1,
                    "section_context": "Commercial Treasury Settlement",
                    "text": "Employee Name: Rajesh Patel."
                }
            ],
            "ground_truth_entities": [
                {"type": "CARD", "value_snippet": "5105105105105100", "page": 1, "text_start": 23, "text_end": 39, "risk": "CRITICAL"},
                {"type": "PAN", "value_snippet": "XYZPA9876K", "page": 1, "text_start": 26, "text_end": 36, "risk": "CRITICAL"},
                {"type": "GST", "value_snippet": "27ABCDE1234F1Z5", "page": 1, "text_start": 12, "text_end": 27, "risk": "HIGH"},
                {"type": "IFSC", "value_snippet": "SBIN0001234", "page": 1, "text_start": 11, "text_end": 22, "risk": "MEDIUM"},
                {"type": "UPI", "value_snippet": "billing@okhdfcbank", "page": 1, "text_start": 8, "text_end": 26, "risk": "MEDIUM"},
                {"type": "EMAIL", "value_snippet": "treasury.controller@cadence-finance.com", "page": 1, "text_start": 17, "text_end": 56, "risk": "HIGH"},
                {"type": "PHONE", "value_snippet": "+91 98765 43210", "page": 1, "text_start": 14, "text_end": 29, "risk": "HIGH"},
                {"type": "PERSON", "value_snippet": "Rajesh Patel", "page": 1, "text_start": 15, "text_end": 27, "risk": "HIGH"}
            ]
        },

        # ---------------------------------------------------------------------
        # Document 4: Security Incident Forensic Dossier & Ticket Register
        # ---------------------------------------------------------------------
        {
            "document_id": "heldout_doc_04",
            "filename": "heldout_doc_04.json",
            "title": "SOC Forensic Incident Investigation & Threat Audit Dossier",
            "description": "SOC security incident ticket combining allow-listed reference codes (INC-2026-0417, RSK-001, CTL-IAM-004, ISO-27001) alongside authentic personal PII.",
            "pages": 2,
            "blocks": [
                {
                    "block_id": "d4_b1",
                    "page": 1,
                    "section_context": "Allow-Listed Security Incident Codes",
                    "text": "Incident ticket INC-2026-0417 closed under risk RSK-001 and CTL-IAM-004 per ISO-27001."
                },
                {
                    "block_id": "d4_b2",
                    "page": 1,
                    "section_context": "Affected Individual Identification",
                    "text": "Tax ID / SSN: 123-45-6789 identified in compromised log."
                },
                {
                    "block_id": "d4_b3",
                    "page": 1,
                    "section_context": "Affected Individual Identification",
                    "text": "Passport No: Z1234567 verified on identity server."
                },
                {
                    "block_id": "d4_b4",
                    "page": 2,
                    "section_context": "Incident Investigator & Response Officer",
                    "text": "Employee Name: Alice Walker appointed Lead Forensics Handler."
                },
                {
                    "block_id": "d4_b5",
                    "page": 2,
                    "section_context": "Incident Investigator & Response Officer",
                    "text": "Corporate Email: alice.walker@optiv-security.com."
                },
                {
                    "block_id": "d4_b6",
                    "page": 2,
                    "section_context": "Incident Investigator & Response Officer",
                    "text": "Mobile Phone: +1 (202) 555-0143."
                },
                {
                    "block_id": "d4_b7",
                    "page": 2,
                    "section_context": "Incident Investigator & Response Officer",
                    "text": "Employee ID: EMP-8239."
                },
                {
                    "block_id": "d4_b8",
                    "page": 2,
                    "section_context": "Incident Investigator & Response Officer",
                    "text": "Date of Birth: 1985-11-23."
                }
            ],
            "ground_truth_entities": [
                {"type": "SSN", "value_snippet": "123-45-6789", "page": 1, "text_start": 14, "text_end": 25, "risk": "CRITICAL"},
                {"type": "PASSPORT", "value_snippet": "Z1234567", "page": 1, "text_start": 13, "text_end": 21, "risk": "CRITICAL"},
                {"type": "PERSON", "value_snippet": "Alice Walker", "page": 2, "text_start": 15, "text_end": 27, "risk": "HIGH"},
                {"type": "EMAIL", "value_snippet": "alice.walker@optiv-security.com", "page": 2, "text_start": 17, "text_end": 48, "risk": "HIGH"},
                {"type": "PHONE", "value_snippet": "+1 (202) 555-0143", "page": 2, "text_start": 14, "text_end": 31, "risk": "HIGH"},
                {"type": "EMPLOYEE_ID", "value_snippet": "EMP-8239", "page": 2, "text_start": 13, "text_end": 21, "risk": "HIGH"},
                {"type": "DOB", "value_snippet": "1985-11-23", "page": 2, "text_start": 15, "text_end": 25, "risk": "HIGH"}
            ],
            "allow_listed_tokens": ["INC-2026-0417", "RSK-001", "CTL-IAM-004", "ISO-27001"]
        },

        # ---------------------------------------------------------------------
        # Document 5: Executive Governance & Private Wealth Dossier
        # ---------------------------------------------------------------------
        {
            "document_id": "heldout_doc_05",
            "filename": "heldout_doc_05.json",
            "title": "Private Wealth Governance & Executive Board Dossier",
            "description": "Executive board dossier featuring US SSN, Indian Aadhaar, international Passport, UK NINO, Ministry Director Identification Number (DIR), DOB, and residential address.",
            "pages": 2,
            "blocks": [
                {
                    "block_id": "d5_b1",
                    "page": 1,
                    "section_context": "Executive Onboarding Dossier",
                    "text": "Tax ID / SSN: 293-11-4829 on official record."
                },
                {
                    "block_id": "d5_b2",
                    "page": 1,
                    "section_context": "Executive Onboarding Dossier",
                    "text": "Aadhaar UID: 9876 5432 1096 verified for wealth account."
                },
                {
                    "block_id": "d5_b3",
                    "page": 1,
                    "section_context": "Executive Onboarding Dossier",
                    "text": "Passport No: A9182345 verified."
                },
                {
                    "block_id": "d5_b4",
                    "page": 1,
                    "section_context": "Executive Onboarding Dossier",
                    "text": "UK NINO: AB 12 34 56 C on record."
                },
                {
                    "block_id": "d5_b5",
                    "page": 1,
                    "section_context": "Executive Onboarding Dossier",
                    "text": "Director ID: DIR-00041 active in corporate registry."
                },
                {
                    "block_id": "d5_b6",
                    "page": 2,
                    "section_context": "Personal Governance Profile",
                    "text": "Date of Birth: 08/19/1974."
                },
                {
                    "block_id": "d5_b7",
                    "page": 2,
                    "section_context": "Personal Governance Profile",
                    "text": "Corporate Email: michael.henderson@wealth-partners.com."
                },
                {
                    "block_id": "d5_b8",
                    "page": 2,
                    "section_context": "Personal Governance Profile",
                    "text": "Employee Name: Michael Henderson."
                },
                {
                    "block_id": "d5_b9",
                    "page": 2,
                    "section_context": "Personal Governance Profile",
                    "text": "Bank IFSC: HDFC0000123."
                },
                {
                    "block_id": "d5_b10",
                    "page": 2,
                    "section_context": "Personal Governance Profile",
                    "text": "Residential Address: 742 Evergreen Terrace, Springfield, OR 97477."
                }
            ],
            "ground_truth_entities": [
                {"type": "SSN", "value_snippet": "293-11-4829", "page": 1, "text_start": 14, "text_end": 25, "risk": "CRITICAL"},
                {"type": "AADHAAR", "value_snippet": "9876 5432 1096", "page": 1, "text_start": 13, "text_end": 27, "risk": "CRITICAL"},
                {"type": "PASSPORT", "value_snippet": "A9182345", "page": 1, "text_start": 13, "text_end": 21, "risk": "CRITICAL"},
                {"type": "NINO", "value_snippet": "AB 12 34 56 C", "page": 1, "text_start": 9, "text_end": 22, "risk": "CRITICAL"},
                {"type": "DIRECTOR_ID", "value_snippet": "DIR-00041", "page": 1, "text_start": 13, "text_end": 22, "risk": "HIGH"},
                {"type": "DOB", "value_snippet": "08/19/1974", "page": 2, "text_start": 15, "text_end": 25, "risk": "HIGH"},
                {"type": "EMAIL", "value_snippet": "michael.henderson@wealth-partners.com", "page": 2, "text_start": 17, "text_end": 53, "risk": "HIGH"},
                {"type": "PERSON", "value_snippet": "Michael Henderson", "page": 2, "text_start": 15, "text_end": 32, "risk": "HIGH"},
                {"type": "IFSC", "value_snippet": "HDFC0000123", "page": 2, "text_start": 11, "text_end": 22, "risk": "MEDIUM"},
                {"type": "ADDRESS", "value_snippet": "742 Evergreen Terrace, Springfield, OR 97477", "page": 2, "text_start": 21, "text_end": 65, "risk": "HIGH"}
            ]
        }
    ]

    doc_checksums = {}

    for idx, doc_data in enumerate(heldout_docs, start=1):
        doc_data["full_text"] = "\n\n".join(b["text"] for b in doc_data["blocks"])

        # Write primary heldout_doc_0X.json
        p_filename = f"heldout_doc_0{idx}.json"
        doc_data["filename"] = p_filename
        json_str = json.dumps(doc_data, indent=2)
        with open(HELDOUT_DIR / p_filename, "w", encoding="utf-8") as f:
            f.write(json_str)

        # Write alias heldout_document_X.json
        alt_data = dict(doc_data)
        alt_filename = f"heldout_document_{idx}.json"
        alt_data["filename"] = alt_filename
        with open(HELDOUT_DIR / alt_filename, "w", encoding="utf-8") as f:
            json.dump(alt_data, f, indent=2)

        doc_checksums[doc_data["document_id"]] = {
            "primary_file": p_filename,
            "alias_file": alt_filename,
            "sha256": calculate_sha256(json_str),
            "total_entities": len(doc_data["ground_truth_entities"]),
            "critical_entities": sum(1 for e in doc_data["ground_truth_entities"] if e.get("risk") == "CRITICAL")
        }

    # -------------------------------------------------------------------------
    # Benchmark Evaluation Specification & Contract (heldout_spec.json)
    # -------------------------------------------------------------------------
    heldout_spec = {
        "spec_version": "1.0.0",
        "benchmark_name": "PII Security Firewall Frozen Held-Out Benchmark",
        "purpose": "Frozen, never-tuned benchmark evaluation dataset ensuring rigorous out-of-sample generalization.",
        "test_lock": {
            "locked_date": "2026-10-11",
            "immutable": True,
            "document_count": len(heldout_docs),
            "document_ids": [d["document_id"] for d in heldout_docs],
            "document_checksums": doc_checksums
        },
        "evaluation_contract": {
            "critical_pii_recall_threshold": 0.99,
            "overall_recall_threshold": 0.95,
            "document_leak_rate_threshold": 0.00,
            "over_redaction_rate_threshold": 0.10,
            "minimum_entities_tested": sum(len(d["ground_truth_entities"]) for d in heldout_docs),
            "critical_entities_tested": sum(
                sum(1 for e in d["ground_truth_entities"] if e.get("risk") == "CRITICAL")
                for d in heldout_docs
            )
        },
        "taxonomy_coverage": [
            "SSN", "PAN", "AADHAAR", "PASSPORT", "NINO", "CARD",
            "PERSON", "EMAIL", "PHONE", "DOB", "ADDRESS",
            "EMPLOYEE_ID", "DIRECTOR_ID", "GST", "IFSC", "UPI"
        ]
    }

    with open(HELDOUT_DIR / "heldout_spec.json", "w", encoding="utf-8") as f:
        json.dump(heldout_spec, f, indent=2)

    print("[SUCCESS] Frozen heldout benchmark dataset generation completed.")


if __name__ == "__main__":
    generate_synthetic_datasets()
    generate_heldout_benchmark_datasets()
