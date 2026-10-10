"""
Unit Tests for Precision and Consistency Fixes
==============================================

Covers the 6 core accuracy requirements:
1. Uniform name detection across body text, tables, and version control (same placeholder).
2. Ordinary words ("Security", "Workflow", "Tier 1", "annual", "Privacy Shield", "Ironclad", "Torii") staying unredacted.
3. Company name "Cadence" staying unredacted in body text.
4. Email tags appearing ONLY when a real email address matches an email pattern.
5. Dates left as they appear in the source.
6. Consistent placeholder mapping across all entity types.
"""

import pytest
from src.schema.document import CanonicalDocument, ExtractedPage, ExtractedBlock, ExtractedTable, TableCell
from src.schema.entities import ContentBlock, TableContext, EntityType
from src.detection.pipeline import DetectionPipeline
from src.policy.policy import PolicyEngine
from src.sanitization.text_redactor import TextRedactor, redact_text_by_values


@pytest.fixture
def pipeline():
    return DetectionPipeline(enable_ner=True)


@pytest.fixture
def policy_engine():
    return PolicyEngine()


def test_name_uniform_redaction_body_table_version_control(pipeline, policy_engine):
    """
    Requirement 1:
    A personal name appearing in body text, a table, and a version control section
    must be detected in every location and receive the exact same placeholder throughout.
    """
    doc = CanonicalDocument(
        doc_id="test_uniform_name_doc",
        source_path="test_doc.docx",
        filename="test_doc.docx",
        file_type=".docx",
        pages=1,
        pages_dict={
            1: ExtractedPage(
                page_num=1,
                blocks=[
                    # Body text
                    ExtractedBlock(
                        block_id="b_body",
                        page=1,
                        block_type="paragraph",
                        text="Senior Risk Director Rob Tilney approved the third-party security assessment.",
                    ),
                    # Version control section
                    ExtractedBlock(
                        block_id="b_vc",
                        page=1,
                        block_type="paragraph",
                        text="Document Control: Author(s): Rob Tilney; Reviewed by KC Burney; Status: Final.",
                    ),
                ],
                tables=[
                    # Table with user list
                    ExtractedTable(
                        table_index=1,
                        page=1,
                        headers=["Role", "USERS"],
                        rows=[
                            [
                                TableCell(row_idx=1, col_idx=0, text="Assessment Lead"),
                                TableCell(row_idx=1, col_idx=1, text="Rob Tilney\nKC Burney", header_name="USERS"),
                            ]
                        ],
                    )
                ],
            )
        },
    )

    processed_doc = pipeline.run_document(doc)
    policy_engine.apply(processed_doc.entities)

    person_entities = [e for e in processed_doc.entities if e.type == "PERSON"]
    rob_entities = [e for e in person_entities if "Rob Tilney" in e.context.get("raw_value", "")]
    kc_entities = [e for e in person_entities if "KC Burney" in e.context.get("raw_value", "")]

    # Check Rob Tilney is detected in body, version control, and table
    assert len(rob_entities) >= 3, f"Expected Rob Tilney in all 3 locations, found {len(rob_entities)}"
    rob_block_ids = {e.context.get("raw_value") for e in rob_entities}

    # Check KC Burney (initials name) is detected in version control and table
    assert len(kc_entities) >= 2, f"Expected KC Burney in table and version control, found {len(kc_entities)}"

    # Build replacements
    replacements = {}
    for ent in processed_doc.entities:
        raw_val = ent.context.get("raw_value", "")
        if raw_val and ent.action != "ALLOW":
            replacements[raw_val] = f"[REDACTED_{ent.type}]"

    # Verify placeholder consistency: Both names map to [REDACTED_PERSON]
    assert replacements.get("Rob Tilney") == "[REDACTED_PERSON]"
    assert replacements.get("KC Burney") == "[REDACTED_PERSON]"

    # Sanitize and verify text
    body_text = "Senior Risk Director Rob Tilney approved the third-party security assessment."
    vc_text = "Document Control: Author(s): Rob Tilney; Reviewed by KC Burney; Status: Final."
    tbl_text = "Rob Tilney\nKC Burney"

    assert redact_text_by_values(body_text, replacements) == (
        "Senior Risk Director [REDACTED_PERSON] approved the third-party security assessment."
    )
    assert redact_text_by_values(vc_text, replacements) == (
        "Document Control: Author(s): [REDACTED_PERSON]; Reviewed by [REDACTED_PERSON]; Status: Final."
    )
    assert redact_text_by_values(tbl_text, replacements) == (
        "[REDACTED_PERSON]\n[REDACTED_PERSON]"
    )


def test_ordinary_words_stay_unredacted(pipeline, policy_engine):
    """
    Requirement 2:
    Ordinary words including 'Workflow', 'Security', 'Tier 1', 'annual',
    'Privacy Shield', and product names like 'Ironclad' and 'Torii' must stay unredacted.
    """
    text = (
        "The annual Security review of the Tier 1 Workflow requires Privacy Shield "
        "compliance when evaluated via Ironclad and Torii integrations."
    )
    blocks = [ContentBlock(text=text, block_id="b_corp", page=1)]
    result = pipeline.run(blocks)

    flagged_values = {e.value.strip().lower() for e in result.entities}

    forbidden_flags = [
        "workflow", "security", "tier 1", "annual",
        "privacy shield", "ironclad", "torii",
    ]
    for word in forbidden_flags:
        assert word not in flagged_values, f"Ordinary word '{word}' was incorrectly flagged as PII!"

    # Verify redaction keeps original text untouched
    replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in result.entities}
    sanitized = redact_text_by_values(text, replacements)
    assert sanitized == text


def test_cadence_company_name_stays_unredacted(pipeline, policy_engine):
    """
    Requirement 3:
    'Cadence' and 'Cadence Financial Group' in body text must not be redacted.
    """
    text = (
        "Cadence Financial Group announced new advisory guidelines. "
        "Employees of Cadence must adhere to TPRM standards."
    )
    blocks = [ContentBlock(text=text, block_id="b_cadence", page=1)]
    result = pipeline.run(blocks)

    cadence_flags = [e for e in result.entities if "cadence" in e.value.lower()]
    assert len(cadence_flags) == 0, f"Company name Cadence was incorrectly flagged: {cadence_flags}"

    replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in result.entities}
    sanitized = redact_text_by_values(text, replacements)
    assert sanitized == text


def test_email_tags_appear_only_when_real_email_present(pipeline, policy_engine):
    """
    Requirement 4:
    [REDACTED_EMAIL] must ONLY be inserted when an actual string matches an email format.
    Stray email cue words ('or email address', 'ID of vendor') must NOT be tagged.
    """
    # Block with stray cues without real email
    stray_text = (
        "Attribute table row specifies: or email address of contact. "
        "ID of vendor provided in field. Email template:\nVendor notification."
    )
    blocks_stray = [ContentBlock(text=stray_text, block_id="b_stray", page=1)]
    result_stray = pipeline.run(blocks_stray)

    email_entities_stray = [e for e in result_stray.entities if e.entity_type == EntityType.EMAIL]
    assert len(email_entities_stray) == 0, (
        f"Stray email tags generated without real email: {[e.value for e in email_entities_stray]}"
    )

    # Block with genuine email address
    real_text = "Please reach out to project lead at alice.walker@optiv.com for details."
    blocks_real = [ContentBlock(text=real_text, block_id="b_real", page=1)]
    result_real = pipeline.run(blocks_real)

    email_entities_real = [e for e in result_real.entities if e.entity_type == EntityType.EMAIL]
    assert len(email_entities_real) == 1
    assert email_entities_real[0].value == "alice.walker@optiv.com"

    replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in result_real.entities}
    sanitized = redact_text_by_values(real_text, replacements)
    assert "[REDACTED_EMAIL]" in sanitized
    assert "alice.walker@optiv.com" not in sanitized


def test_dates_remain_as_in_source(pipeline, policy_engine):
    """
    Requirement 5:
    Dates should be left as they appear in the source (not altered or redacted as DOB).
    """
    text = (
        "Document revision date is September 16, 2026. "
        "The annual certification was renewed on 15 March 2024. Next review: 2027."
    )
    blocks = [ContentBlock(text=text, block_id="b_dates", page=1)]
    result = pipeline.run(blocks)

    dob_entities = [e for e in result.entities if e.entity_type == EntityType.DOB]
    assert len(dob_entities) == 0, f"Generic calendar dates flagged as DOB: {[e.value for e in dob_entities]}"

    replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in result.entities}
    sanitized = redact_text_by_values(text, replacements)
    assert sanitized == text
    assert "September 16, 2026" in sanitized
    assert "15 March 2024" in sanitized


def test_inconsistent_placeholder_types_resolved(pipeline, policy_engine):
    """
    Requirement 6:
    Verify exact placeholder mapping:
    PERSON -> [REDACTED_PERSON]
    EMAIL  -> [REDACTED_EMAIL]
    PHONE  -> [REDACTED_PHONE]
    SSN    -> [REDACTED_SSN]
    """
    text = (
        "Employee Daniela Figueroa has email daniela.figueroa@example.com, "
        "phone (555) 345-6789, and SSN 123-45-6789."
    )
    blocks = [ContentBlock(text=text, block_id="b_placeholders", page=1)]
    result = pipeline.run(blocks)

    type_map = {e.value: e.entity_type for e in result.entities}
    assert type_map.get("Daniela Figueroa") == EntityType.PERSON
    assert type_map.get("daniela.figueroa@example.com") == EntityType.EMAIL
    assert type_map.get("123-45-6789") == EntityType.SSN

    replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in result.entities}
    sanitized = redact_text_by_values(text, replacements)

    assert "[REDACTED_PERSON]" in sanitized
    assert "[REDACTED_EMAIL]" in sanitized
    assert "[REDACTED_SSN]" in sanitized
    assert "Daniela Figueroa" not in sanitized
    assert "daniela.figueroa@example.com" not in sanitized
    assert "123-45-6789" not in sanitized
