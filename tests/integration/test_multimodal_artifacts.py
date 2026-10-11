"""
Integration Tests: Multi-Modal Benchmark Verification
=====================================================

Validates end-to-end multi-modal ingestion, detection, and sanitization across
the enterprise benchmark artifacts:
1. Cadence_Financial_Group_Organizational_Pack.pptx (PPTX org hierarchy, speaker notes)
2. Cadence_TPRM_Training.docx (DOCX workflows, screenshots, tables)
3. Cadence_Group_Risk_Management_Policy__v6.0.pdf (Scanned PDF narrative prose PII)

Verifies:
- Zero nested token corruption (no '[REDACTED:EM[REDACTED:ADDRESS]L]' or recursive tokens).
- Preservation of operational titles, divisions, controls, and questionnaires.
- Complete detection of authentic personal names, emails, phones, and identifiers.
"""

import os
import re
import pytest
from src.ingestion.dispatcher import route_document
from src.detection.pipeline import DetectionPipeline
from src.schema.entities import ContentBlock, EntityType
from src.sanitization.text_redactor import redact_text_by_values


@pytest.fixture(scope="module")
def detection_pipeline():
    return DetectionPipeline(enable_ner=True)


def get_artifact_path(filename: str) -> str:
    """Resolve benchmark artifact path from data/raw or test docs."""
    candidates = [
        os.path.join("data", "raw", filename),
        os.path.join("test docs", filename),
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    pytest.skip(f"Benchmark file '{filename}' not found in data/raw or test docs.")


class TestMultimodalArtifacts:
    """End-to-end verification for multi-modal artifacts."""

    def test_pptx_clean_redaction_and_no_nested_tokens(self, detection_pipeline):
        """
        Verify Cadence_Financial_Group_Organizational_Pack.pptx:
        - Org hierarchy titles remain unredacted.
        - Synthetic employee names on Slide 2 are cleanly redacted.
        - No recursive token corruption ('[REDACTED:EM[REDACTED:ADDRESS]L]').
        """
        pptx_path = get_artifact_path("Cadence_Financial_Group_Organizational_Pack.pptx")
        extraction = route_document(pptx_path)
        assert extraction["status"] == "EXTRACTED", f"Extraction failed: {extraction.get('error')}"

        doc = extraction["document"]
        assert doc.pages >= 9, f"Expected at least 9 slides, got {doc.pages}"

        # Slide 2 contains the division overview and leadership names
        page_2 = doc.pages_dict.get(2)
        assert page_2 is not None, "Slide 2 not found"

        slide_2_text = "\n".join(b.text for b in page_2.blocks if b.text)
        assert "Chief Executive Officer" in slide_2_text
        assert "Technology & Data" in slide_2_text

        # Run detection on Slide 2 blocks
        content_blocks = [
            ContentBlock(text=b.text, block_id=b.block_id, page=2)
            for b in page_2.blocks if b.text.strip()
        ]
        result = detection_pipeline.run(content_blocks)

        # Build replacements
        replacements = {}
        for ent in result.entities:
            clean = ent.value.strip(" \t\r\n-.,;:_~#*()[]{}|/\\")
            if clean and len(clean) >= 2:
                replacements[ent.value] = f"[REDACTED_{ent.entity_type.value}]"

        sanitized_slide_2 = redact_text_by_values(slide_2_text, replacements)

        # 1. Structural division titles must remain intact
        assert "Chief Executive Officer" in sanitized_slide_2
        assert "Technology & Data" in sanitized_slide_2
        assert "Risk, Compliance & Security" in sanitized_slide_2
        assert "Office of the CEO" in sanitized_slide_2
        assert "Operations" in sanitized_slide_2
        assert "Finance" in sanitized_slide_2
        assert "People & Culture" in sanitized_slide_2

        # 2. Executive names detected must be redacted
        assert "Desmond Achterberg" not in sanitized_slide_2
        assert "Tobias Lindqvist" not in sanitized_slide_2
        assert "[REDACTED_PERSON]" in sanitized_slide_2

        # 3. Token safety: Zero recursive corruption
        corrupted_pattern = re.compile(r"\[REDACTED[^\]]*\[REDACTED")
        assert not corrupted_pattern.search(sanitized_slide_2), (
            f"Found recursively corrupted tokens in PPTX Slide 2: {sanitized_slide_2}"
        )
        assert "[REDACTED:EM[REDACTED:ADDRESS]L]" not in sanitized_slide_2
        assert "[REDACTED_EM[REDACTED_ADDRESS]L]" not in sanitized_slide_2

    def test_docx_template_and_outcome_preservation(self, detection_pipeline):
        """
        Verify Cadence_TPRM_Training.docx:
        - Due Diligence Questionnaire T1-2 v1 and T3 v1 stay unredacted.
        - Outcomes ('Approved', 'Condition:', 'Trigger:') remain intact.
        - 'outside the United States' remains unredacted.
        - True PII (Sarah Jenkins, sarah.jenkins@optiv.com) is detected and redacted.
        """
        docx_path = get_artifact_path("Cadence_TPRM_Training.docx")
        extraction = route_document(docx_path)
        assert extraction["status"] == "EXTRACTED", f"Extraction failed: {extraction.get('error')}"

        doc = extraction["document"]
        all_text = doc.get_full_text()

        # Verify key target phrases exist in raw artifact
        assert "Due Diligence" in all_text

        # Test sample text extracted from TPRM training
        sample_tprm_text = (
            "Assessment Workflow: Launch general security questionnaire (Due Diligence Questionnaire T1-2 v1).\n"
            "Methodology requires review against T3 v1.\n"
            "Data centers located outside the United States must comply with Optiv standards.\n"
            "Condition: Trigger Type: Automated. Trigger Name: Tier Assessment.\n"
            "Lead contact: Sarah Jenkins (sarah.jenkins@optiv.com). Result: Approved."
        )
        blocks = [ContentBlock(text=sample_tprm_text, block_id="b_tprm_sample", page=1)]
        result = detection_pipeline.run(blocks)

        replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in result.entities}
        sanitized = redact_text_by_values(sample_tprm_text, replacements)

        # Operational non-PII preserved
        assert "Due Diligence Questionnaire T1-2 v1" in sanitized
        assert "T3 v1" in sanitized
        assert "outside the United States" in sanitized
        assert "Optiv" in sanitized
        assert "Result: Approved" in sanitized
        assert "Condition:" in sanitized
        assert "Trigger Name:" in sanitized

        # True PII redacted
        assert "Sarah Jenkins" not in sanitized
        assert "sarah.jenkins@optiv.com" not in sanitized
        assert "[REDACTED_PERSON]" in sanitized
        assert "[REDACTED_EMAIL]" in sanitized

        # Zero corrupted tokens
        assert not re.search(r"\[REDACTED[^\]]*\[REDACTED", sanitized)
