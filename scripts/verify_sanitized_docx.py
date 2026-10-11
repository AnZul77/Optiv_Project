import os
import sys
sys.path.insert(0, os.path.abspath("."))
import docx
import zipfile
import re
from src.security.integrity import DocumentIntegrityGuard

san_path = "data/outputs/sanitized_Cadence_TPRM_Training.docx"
raw_path = "data/raw/Cadence_TPRM_Training.docx"

print("============================================================")
print("  DOCX SPECIALIST VERIFICATION REPORT")
print("============================================================")

# 1. Open and Integrity Check
check = DocumentIntegrityGuard.verify_document(san_path)
print(f"1. DocumentIntegrityGuard valid: {check.is_valid} (Error: {check.error})")
assert check.is_valid, f"Integrity check failed: {check.error}"

# 2. XML Structure & Tables
doc_raw = docx.Document(raw_path)
doc_san = docx.Document(san_path)

print(f"2. Paragraph Count: raw={len(doc_raw.paragraphs)}, san={len(doc_san.paragraphs)}")
assert len(doc_raw.paragraphs) == len(doc_san.paragraphs)

print(f"3. Table Count: raw={len(doc_raw.tables)}, san={len(doc_san.tables)}")
assert len(doc_raw.tables) == len(doc_san.tables) == 16

for i, (tr, ts) in enumerate(zip(doc_raw.tables, doc_san.tables)):
    assert len(tr.rows) == len(ts.rows), f"Table {i} rows mismatch!"
    assert len(tr.columns) == len(ts.columns), f"Table {i} columns mismatch!"
print("   All 16 tables match exact rows and column dimensions.")

# 4. Embedded Media Relationships
with zipfile.ZipFile(raw_path) as z_r, zipfile.ZipFile(san_path) as z_s:
    media_raw = set(f for f in z_r.namelist() if f.startswith("word/media/"))
    media_san = set(f for f in z_s.namelist() if f.startswith("word/media/"))
    print(f"4. Embedded Media Count: raw={len(media_raw)}, san={len(media_san)}")
    assert media_raw == media_san, "Media files mismatch!"
print("   All embedded OneTrust screenshots and media files are 100% intact.")

# 5. Check Target Personal Names
target_names = [
    "Daniela Figueroa",
    "Bridgett Gatewood",
    "KC Burney",
    "Rob Tilney",
    "Chris Ott",
    "Melisa Cardozo",
    "DK Koran",
    "Erik Hansen",
    "Jyoti Karwal",
    "Tamika Oliver",
    "Shimane Smith",
    "Chris Schmitz",
    "Jonathan Szeto",
    "Marc Otani",
    "Dayo Seton",
    "Siddharth Gaikwad",
    "Srinivas Teppa",
    "Nikhil Karkera",
    "Jonathan Edwards",
]

# Extract all text from sanitized document
san_text_parts = []
for p in doc_san.paragraphs:
    san_text_parts.append(p.text)
for t in doc_san.tables:
    for row in t.rows:
        for c in row.cells:
            san_text_parts.append(c.text)
for elem in doc_san.element.xpath(".//w:txbxContent//w:p"):
    san_text_parts.append(elem.text or "")
san_full_text = "\n".join(san_text_parts)

print("\n5. Verification of Authentic Personal Names (must be 0 in sanitized doc):")
for name in target_names:
    count = san_full_text.lower().count(name.lower())
    print(f"   - {name:20}: {count} occurrences (Expected: 0)")
    assert count == 0, f"Found unredacted personal name: {name}!"

# 6. Check Operational / Business Terminology (must remain unredacted)
operational_terms = [
    "Due Diligence Questionnaire T1-2 v1",
    "Due Diligence Questionnaire T3 v1",
    "Approved",
    "Condition:",
    "Trigger:",
    "Trigger Name:",
    "Rule Name",
    "Ironclad",
    "Torii",
    "Optiv",
    "United States",
    "Appendix A",
    "Appendix B",
    "Appendix C",
    "Appendix D",
    "Appendix E",
    "QA Reviewer",
    "Admin",
    "Workflow",
    "Security",
]

print("\n6. Verification of Operational / Business Terminology:")
for term in operational_terms:
    count = san_full_text.count(term)
    print(f"   - {term:36}: {count} occurrences (Must be > 0)")
    assert count > 0, f"Operational term missing or erroneously redacted: {term}!"

# 7. Check specific tables:
# Table 4 USERS column must only contain [REDACTED_PERSON]
print("\n7. Checking Table 4 (User Groups & USERS column):")
t4 = doc_san.tables[4]
for r_idx in range(1, len(t4.rows)):
    user_cell_text = t4.rows[r_idx].cells[3].text.strip()
    permissions = t4.rows[r_idx].cells[2].text.strip()
    group_name = t4.rows[r_idx].cells[0].text.strip()
    print(f"   Row {r_idx} [{group_name} | {permissions}]:\n     {user_cell_text.replace(chr(10), ' | ')}")
    assert "[REDACTED_PERSON]" in user_cell_text
    # Ensure no personal name leaks in this cell
    for name in target_names:
        assert name.lower() not in user_cell_text.lower()

# Table 14 Metadata & Reviewers
print("\n8. Checking Table 14 (Document Control / Reviewers):")
t14 = doc_san.tables[14]
for r_idx in range(len(t14.rows)):
    row_txt = [c.text.strip() for c in t14.rows[r_idx].cells]
    print(f"   Row {r_idx}: {row_txt}")

assert t14.rows[2].cells[1].text.strip() == "[REDACTED_PERSON]"  # Client Contact: Daniela Figueroa
assert t14.rows[4].cells[1].text.strip() == "[REDACTED_PERSON], [REDACTED_PERSON]"  # Author(s): Siddharth Gaikwad, Srinivas Teppa
assert t14.rows[5].cells[1].text.strip() == "[REDACTED_PERSON]"  # Peer Reviewer: Nikhil Karkera
assert t14.rows[6].cells[0].text.strip() == "QA Reviewer"  # Label QA Reviewer intact!

print("\n[SUCCESS] ALL VERIFICATION CHECKS PASSED PERFECTLY!")
