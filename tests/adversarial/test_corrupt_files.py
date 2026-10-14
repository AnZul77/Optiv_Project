"""
Adversarial Testing: Corrupt, Malformed, and Low-Confidence Ingestion Cases
Person 5: Evaluation Benchmark, Adversarial Testing & UI Lead
Roadmap: Day 12 / 17 Adversarial Robustness Suite

Validates that corrupted files, hostile archives, malformed magic bytes,
and low-confidence OCR scans strictly fail-closed and NEVER leak or pass through.
"""

import os
import tempfile
import zipfile
import pytest

from src.ingestion.validators import validate_document
from src.security.limits import (
    SecurityLimitsConfig,
    check_file_size,
    inspect_archive_safety,
    inspect_xml_content_safety,
    SecurityLimitExceededError,
    MalformedFileError,
)
from src.security.integrity import DocumentIntegrityGuard
from src.verification.gate import AIReadinessGate, BLOCK, PASS
from src.verification.verifier import IndependentVerifier
from src.policy.policy import PolicyEngine


class TestAdversarialCorruptFiles:
    """Test suite ensuring corrupted, hostile, and low-confidence inputs fail-closed."""

    def test_zero_byte_empty_file_rejected(self):
        """Empty 0-byte file must fail pre-flight validation."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            res = validate_document(tmp_path)
            assert res.is_valid is False
            assert "empty" in (res.error or "").lower()
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_invalid_magic_bytes_rejected(self):
        """A file with mismatched magic bytes (e.g. text masquerading as PDF) is rejected."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(b"Plain text masquerading as a PDF document without %PDF- header.")
            tmp_path = tmp.name

        try:
            res = validate_document(tmp_path)
            assert res.is_valid is False
            assert "magic byte" in (res.error or "").lower()
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_zip_bomb_expansion_ratio_blocked(self):
        """An archive designed with an extreme decompression ratio triggers security limits."""
        cfg = SecurityLimitsConfig(
            max_file_size_bytes=10 * 1024 * 1024,
            max_uncompressed_bytes=50 * 1024 * 1024,
            max_compression_ratio=10.0,  # Enforce low threshold for test
        )

        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Create a zip containing highly compressible zeros
            with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                large_content = b"\x00" * (1024 * 1024)  # 1 MB of zeros compresses to ~1 KB
                zf.writestr("word/document.xml", large_content)

            with pytest.raises(SecurityLimitExceededError) as exc_info:
                inspect_archive_safety(tmp_path, cfg)
            assert "ratio" in str(exc_info.value).lower()
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_xxe_external_entity_blocked(self):
        """Malicious XML containing <!ENTITY SYSTEM ...> is flagged and blocked."""
        malicious_xml = b"""<?xml version="1.0"?>
        <!DOCTYPE doc [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <doc>&xxe;</doc>"""

        with pytest.raises(SecurityLimitExceededError) as exc_info:
            inspect_xml_content_safety(malicious_xml)
        assert "xxe" in str(exc_info.value).lower() or "entity" in str(exc_info.value).lower()

    def test_low_confidence_ocr_rotated_scan_blocked(self):
        """
        Rotated scans (90° / 180°) or noisy pages produce low OCR confidence (< 0.60).
        The AI Gate must strictly fail-closed and evaluate to BLOCK.
        """
        verifier = IndependentVerifier()
        clean_report = verifier.verify_text("Executive report summary text.")

        policy = PolicyEngine()
        policy_res = policy.apply([])

        gate = AIReadinessGate()
        # Simulate a 90-degree rotated page yielding low average confidence (0.38)
        decision = gate.evaluate(
            document_id="doc_rotated_page",
            verifier_report=clean_report,
            policy_result=policy_res,
            ocr_confidences={1: 0.38},
        )

        assert decision.decision == BLOCK
        assert decision.ai_ready is False
        assert any(r.code == "LOW_CONFIDENCE_UNCERTAINTY" for r in decision.reasons)

    def test_corrupt_document_integrity_guard_fails_closed(self):
        """Truncated or corrupted output file must fail the post-redaction integrity check."""
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tmp:
            tmp.write(b"PK\x03\x04" + b"\x00" * 50)  # Truncated zip header
            tmp_path = tmp.name

        try:
            res = DocumentIntegrityGuard.verify_document(tmp_path)
            assert res.is_valid is False
            assert "corrupt" in (res.error or "").lower() or "invalid" in (res.error or "").lower()
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
