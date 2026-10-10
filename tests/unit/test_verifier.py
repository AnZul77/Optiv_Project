"""
Unit Tests: Independent Secondary Verifier (Person 4)
=====================================================

The verifier must (a) catch PII the primary detector can miss, including
adversarial encodings, (b) stay quiet on sanitized text and business prose,
(c) never put raw values in its report, and (d) be independent of
src.detection.
"""

import ast
from pathlib import Path

import pytest

from src.schema.document import CanonicalDocument, ExtractedBlock, ExtractedPage
from src.schema.entities import ContentBlock, compute_value_hash
from src.verification.verifier import (
    IndependentVerifier,
    luhn_valid,
    shannon_entropy,
    verhoeff_valid,
    verify_document,
)


@pytest.fixture(scope="module")
def verifier():
    return IndependentVerifier.from_policy()


def _types(report):
    return {f.entity_type for f in report.findings}


class TestIndependence:
    def test_does_not_import_primary_detector(self):
        path = Path(__file__).resolve().parents[2] / "src" / "verification" / "verifier.py"
        source = path.read_text(encoding="utf-8")
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        assert not any(name.startswith("src.detection") for name in imported)


class TestDetectsResidualPII:
    @pytest.mark.parametrize("text,expected", [
        ("Employee SSN 219-45-7890 on file", "SSN"),
        ("Card 4111 1111 1111 1111 charged", "CARD"),
        ("UID 2345 6789 0124", "AADHAAR"),
        ("Director PAN ABCPE1234F", "PAN"),
        ("NI number AB 12 34 56 C", "NINO"),
        ("Passport No. K1234567 issued in Pune", "PASSPORT"),
        ("Date of Birth (DD/MM/YYYY): 14/07/1988", "DOB"),
        ("reach me at alice.walker@optiv-security.com", "EMAIL"),
        ("mobile +1 (415) 555-2671", "PHONE"),
        ("CEO direct line is +1-555-0199.", "PHONE"),
        ("Staff ID: EMP-908234", "EMPLOYEE_ID"),
        ("Account No: 001234567890", "BANK_ACCOUNT"),
        ("Tax ID: 12-3456789", "TAX_ID"),
        ("Name: Alice Vance", "PERSON"),
        ("Approved by Dr. Priya Raman", "PERSON"),
        ("Lives at 221 Baker Street", "ADDRESS"),
        ("IFSC SBIN0001234", "IFSC"),
        ("GSTIN 27ABCDE1234F1Z5", "GST"),
        ("Pay to rahul.s@okaxis", "UPI"),
        ("Reference 739182046 noted", "NUMERIC_ID"),
    ])
    def test_plain_pii(self, verifier, text, expected):
        report = verifier.verify_text(text)
        assert not report.passed
        assert expected in _types(report)

    @pytest.mark.parametrize("text,expected", [
        ("S S N : 1 2 3 - 4 5 - 6 7 8 9", "SSN"),                 # character spacing
        ("SSN: 2​1​9-45-7890", "SSN"),                   # zero-width spaces
        ("ЅЅN: 123-45-6789", "SSN"),                     # Cyrillic homoglyphs
        ("SSN：２１９-45-7890", "SSN"),            # full-width digits
        ("SSN 219–45–7890", "SSN"),                      # en-dashes
        ("Approved by R a h u l today", "PERSON"),                 # spaced name
        ("write to john.doe [at] example [dot] com", "EMAIL"),     # obfuscated email
        ("Ticket INC-2026-219457890 raised", "NUMERIC_ID"),        # allow-list smuggling
    ])
    def test_adversarial_encodings(self, verifier, text, expected):
        report = verifier.verify_text(text)
        assert expected in _types(report), report.to_dict()

    def test_offsets_map_back_to_original_text(self, verifier):
        text = "SSN: 2​1​9-45-7890 end"
        finding = verifier.verify_text(text).findings[0]
        assert text[finding.start:finding.end] == "2​1​9-45-7890"

    def test_overlapping_detectors_merged(self, verifier):
        report = verifier.verify_text("SSN: 219-45-7890")
        assert len(report.findings) == 1
        assert "+" in report.findings[0].detector


class TestNoFalsePositives:
    @pytest.mark.parametrize("text", [
        "Name: [REDACTED_PERSON], SSN: [REDACTED_SSN], Email: [REDACTED_EMAIL]",
        "SSN: ███████████",
        "Audit INC-2026-0417 maps to RSK-117, GRP-POL-001 and CTL-IAM-004.",
        "Compliant with ISO 27001:2013 and NIST SP 800-53 Rev. 5, Section 3.2.1, v6.0.",
        "Page 22 of 35. Effective 14 July 2024. Reviewed 2024-01-15.",
        "Fiscal years 2024 2025 2026 2027",
        "Budget USD 10,000,000 approved; 1,234,567 records; 45% coverage.",
        "Prepared by: Group Risk Management. Approved by: Board Risk Committee.",
        "Section 4.2 Tax ID: requirements for 2024 filings",
        "File name: Risk Policy Final",
        "C O N F I D E N T I A L",
    ])
    def test_clean_text_passes(self, verifier, text):
        report = verifier.verify_text(text)
        assert report.passed, report.to_dict()


class TestReport:
    def test_no_raw_values_in_report(self, verifier):
        report = verifier.verify_text("SSN 219-45-7890, mail alice@corp.com")
        dumped = str(report.to_dict())
        assert "219-45-7890" not in dumped and "alice@corp.com" not in dumped
        assert report.findings[0].value_hash == compute_value_hash("219-45-7890")

    def test_empty_input_is_uncertain(self, verifier):
        report = verifier.verify_units([])
        assert report.uncertain and not report.passed
        assert report.status_code == "VERIFIER_UNCERTAIN"

    def test_scanner_fault_is_uncertain_not_crash(self, verifier, monkeypatch):
        def boom(*args, **kwargs):
            raise RuntimeError("boom")
        monkeypatch.setattr(verifier, "scan_text", boom)
        report = verifier.verify_text("anything")
        assert report.uncertain and not report.passed
        assert report.residual_risk == "CRITICAL"

    def test_merge_and_status(self, verifier):
        clean = verifier.verify_text("nothing here")
        dirty = verifier.verify_text("SSN 219-45-7890")
        merged = clean.merge(dirty)
        assert merged.units_scanned == 2
        assert merged.status_code == "RESIDUAL_LEAK_DETECTED"
        assert merged.residual_risk == "CRITICAL"
        assert clean.status_code == "VERIFIED_CLEAN"


class TestInputs:
    def test_blocks(self, verifier):
        blocks = [ContentBlock(text="ok", block_id="b1", page=1),
                  ContentBlock(text="SSN 219-45-7890", block_id="b2", page=4)]
        report = verifier.verify_blocks(blocks)
        assert report.findings[0].unit_id == "b2"
        assert report.findings[0].page == 4

    def test_canonical_document_all_channels(self, verifier):
        doc = CanonicalDocument(doc_id="d", source_path="x", filename="x.pptx", file_type=".pptx", pages=1)
        page = ExtractedPage(page_num=1, native_text="Slide title")
        page.blocks = [ExtractedBlock("s1", 1, "slide_shape", "Slide title"),
                       ExtractedBlock("n1", 1, "speaker_note", "CEO direct line is +1-555-0199.",
                                      is_hidden=True)]
        doc.add_page(page)
        doc.metadata = {"core": {"author": "Mr. John Smith"}}
        report = verifier.verify_document(doc)
        sources = {f.source for f in report.findings}
        assert {"block", "metadata"} <= sources

    def test_module_level_entry_point(self):
        assert verify_document("SSN 219-45-7890").status_code == "RESIDUAL_LEAK_DETECTED"
        assert verify_document([ContentBlock(text="fine", block_id="b")]).passed


class TestValidators:
    def test_luhn(self):
        assert luhn_valid("4111 1111 1111 1111")
        assert not luhn_valid("4111 1111 1111 1112")

    def test_verhoeff(self):
        assert verhoeff_valid("234567890124")
        assert not verhoeff_valid("202420252026")

    def test_entropy(self):
        assert shannon_entropy("111111111") == 0.0
        assert shannon_entropy("739182046") > 3.0


class TestDenialOfService:
    """Crafted long tokens must not trigger quadratic regex backtracking."""

    @pytest.mark.parametrize(
        "payload",
        ["a" * 50000, "a." * 25000, "1 " * 25000, "a [at] " * 7000],
        ids=["50k_a", "25k_dots", "25k_spaces", "7k_at"],
    )
    def test_pathological_input_is_fast(self, verifier, payload):

        import time

        started = time.perf_counter()
        verifier.verify_text(payload)
        assert time.perf_counter() - started < 3.0
