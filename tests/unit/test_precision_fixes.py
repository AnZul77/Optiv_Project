"""
Unit Tests for Precision, Consistency, and Defect Fixes
======================================================

Covers the complete defect catalog and PRD accuracy requirements:
1. Uniform name detection across body text, tables, and version control (same placeholder).
2. Category 1: Questionnaire & Template names ('Due Diligence Questionnaire T1-2 v1', 'T3 v1') stay unredacted.
3. Category 2: Outcome & result values ('Result: Approved', 'The third-party is Approved', 'Rejected', 'Conditional') stay unredacted and are not tagged as ADDRESS or PERSON.
4. Category 3: Companies, tools & jurisdictions ('Ironclad', 'Torii', 'Contract' in forms, 'outside the United States', 'Optiv') stay unredacted and not mislabeled as ADDRESS.
5. Category 4: Field labels and structure ('Condition:', 'Trigger:', 'Trigger Type:', 'Trigger Name:', 'Rule Name', 'Email ID', 'Vendor Tier attribute', 'Appendix A'-'E', 'QA Reviewer') stay unredacted.
6. Category 5: Ordinary words ('Admin', 'custom', 'templates', 'trigger', 'description', 'Artificial Intelligence', 'Security Team', 'Launch', 'Email', 'annual', 'Tier 3 third parties') stay unredacted.
7. Category 6: Group/approver names ('Vendor Risk Management Group', 'Information Security Committee') stay unredacted.
8. Category 7: Multi-modal token safety & nesting prevention (no '[REDACTED:EM[REDACTED:ADDRESS]L]' or recursive token mutation).
9. Adversarial evasion cases (casing, punctuation, mixed embedding).
"""

import re
import pytest
from src.schema.document import CanonicalDocument, ExtractedPage, ExtractedBlock, ExtractedTable, TableCell
from src.schema.entities import ContentBlock, TableContext, EntityType, Action, PIIEntity
from src.detection.pipeline import DetectionPipeline
from src.policy.policy import PolicyEngine
from src.sanitization.text_redactor import TextRedactor, redact_text_by_values, redact_text_by_spans


@pytest.fixture
def pipeline():
    return DetectionPipeline(enable_ner=True)


@pytest.fixture
def policy_engine():
    return PolicyEngine()


# =============================================================================
# Baseline Consistency Requirements
# =============================================================================

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


# =============================================================================
# Defect Category 1: Questionnaire & Template Names
# =============================================================================

def test_defect_1_questionnaire_and_template_names(pipeline):
    """
    Defect Category 1:
    Questionnaire and template identifiers such as 'Due Diligence Questionnaire T1-2 v1',
    'T3 v1', and 'Due Diligence Questionnaire' must remain unredacted and never be flagged
    as PERSON or propagated across document blocks.
    """
    sample_text = (
        "Template: Due Diligence Questionnaire T1-2 v1. "
        "Launch general security questionnaire (Due Diligence Questionnaire T1-2 v1). "
        "Complete T3 v1 before vendor onboarding. "
        "Third parties must complete Due Diligence Questionnaire per policy."
    )
    blocks = [ContentBlock(text=sample_text, block_id="b_tmpl_1", page=1)]
    result = pipeline.run(blocks)

    flagged_lower = {e.value.strip().lower() for e in result.entities}
    forbidden_terms = [
        "due diligence questionnaire t1-2 v1",
        "due diligence questionnaire",
        "diligence questionnaire",
        "t1-2 v1",
        "t3 v1",
    ]
    for term in forbidden_terms:
        assert term not in flagged_lower, f"Template name '{term}' was erroneously flagged as PII: {flagged_lower}"

    replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in result.entities}
    sanitized = redact_text_by_values(sample_text, replacements)
    assert "Due Diligence Questionnaire T1-2 v1" in sanitized
    assert "T3 v1" in sanitized
    assert "Due Diligence Questionnaire" in sanitized
    assert "[REDACTED_PERSON] T1-2 v1" not in sanitized

    # Multi-block propagation safety check
    doc = CanonicalDocument(
        doc_id="test_tmpl_propagation",
        source_path="tmpl.docx",
        filename="tmpl.docx",
        file_type=".docx",
        pages=1,
        pages_dict={
            1: ExtractedPage(
                page_num=1,
                blocks=[
                    ExtractedBlock(
                        block_id="b1", page=1, block_type="paragraph",
                        text="Assessment conducted according to Due Diligence Questionnaire T1-2 v1."
                    ),
                    ExtractedBlock(
                        block_id="b2", page=1, block_type="paragraph",
                        text="Vendor responded to T3 v1 and Due Diligence Questionnaire."
                    ),
                ]
            )
        }
    )
    processed_doc = pipeline.run_document(doc)
    doc_flagged = {e.context.get("raw_value", "").strip().lower() for e in processed_doc.entities}
    for term in forbidden_terms:
        assert term not in doc_flagged, f"Template term '{term}' propagated as PII in multi-block document!"


# =============================================================================
# Defect Category 2: Outcome & Result Values
# =============================================================================

def test_defect_2_outcome_and_result_values(pipeline):
    """
    Defect Category 2:
    Outcome and decision values like 'Result: Approved', 'The third-party is Approved',
    'Rejected', 'Conditional', and 'Submitted' must remain unredacted and never be flagged
    as ADDRESS, LOCATION, or PERSON.
    """
    blocks = [
        ContentBlock(text="The third-party is Approved", block_id="b_out1", page=1),
        ContentBlock(text="Result: Approved", block_id="b_out2", page=1),
        ContentBlock(text="Vendor Risk Status: Rejected", block_id="b_out3", page=1),
        ContentBlock(text="Evaluation Decision: Conditional approval granted", block_id="b_out4", page=1),
        ContentBlock(text="Intake Form was Submitted for review", block_id="b_out5", page=1),
    ]
    result = pipeline.run(blocks)

    flagged_dict = {e.value.strip().lower(): e.entity_type for e in result.entities}
    outcomes = ["approved", "rejected", "conditional", "submitted"]
    for outcome in outcomes:
        assert outcome not in flagged_dict, (
            f"Decision status '{outcome}' was erroneously flagged as {flagged_dict.get(outcome)}!"
        )

    replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in result.entities}
    for b in blocks:
        sanitized = redact_text_by_values(b.text, replacements)
        assert "[REDACTED_ADDRESS]" not in sanitized
        assert "[REDACTED:ADDRESS]" not in sanitized
        assert "[REDACTED_PERSON]" not in sanitized
        assert b.text == sanitized

    # Contrast with authentic person and email while outcome remains intact
    mixed_text = "The third-party is Approved for applicant Sarah Connor with email sconnor@optiv.com."
    mixed_blocks = [ContentBlock(text=mixed_text, block_id="b_mixed_outcome", page=1)]
    mixed_result = pipeline.run(mixed_blocks)

    mixed_replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in mixed_result.entities}
    mixed_sanitized = redact_text_by_values(mixed_text, mixed_replacements)

    assert "The third-party is Approved" in mixed_sanitized
    assert "Sarah Connor" not in mixed_sanitized
    assert "[REDACTED_PERSON]" in mixed_sanitized
    assert "sconnor@optiv.com" not in mixed_sanitized
    assert "[REDACTED_EMAIL]" in mixed_sanitized


# =============================================================================
# Defect Category 3: Companies, Tools & Jurisdictions
# =============================================================================

def test_defect_3_companies_tools_and_jurisdictions(pipeline):
    """
    Defect Category 3:
    Company, product, tool, and country terms ('Ironclad', 'Torii', 'Contract' in
    'Contract Submission Form' and 'Contract creation', 'outside the United States',
    'Optiv') must stay unredacted and not be mislabeled as ADDRESS.
    """
    text = (
        "Contract Submission Form must be completed inside Ironclad. "
        "Contract creation in Ironclad for Optiv is coordinated with Torii. "
        "Data centers operate outside the United States. "
        "Optiv validates regulatory requirements within the United States."
    )
    blocks = [ContentBlock(text=text, block_id="b_tools_jurisdictions", page=1)]
    result = pipeline.run(blocks)

    address_entities = [e.value.lower() for e in result.entities if e.entity_type == EntityType.ADDRESS]
    person_entities = [e.value.lower() for e in result.entities if e.entity_type == EntityType.PERSON]

    for term in ["united states", "the united states", "ironclad", "torii", "optiv", "contract"]:
        assert term not in address_entities, f"Term '{term}' was mislabeled as ADDRESS!"
        assert term not in person_entities, f"Term '{term}' was mislabeled as PERSON!"

    replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in result.entities}
    sanitized = redact_text_by_values(text, replacements)

    assert "Contract Submission Form" in sanitized
    assert "Contract creation" in sanitized
    assert "Ironclad" in sanitized
    assert "Torii" in sanitized
    assert "Optiv" in sanitized
    assert "outside the United States" in sanitized
    assert "within the United States" in sanitized
    assert "outside [REDACTED_ADDRESS]" not in sanitized
    assert "Outside [REDACTED_ADDRESS]" not in sanitized

    # Contrast with authentic headquarters location
    hq_text = "Optiv headquarters is located at 1144 15th Street, Suite 2900, Denver, CO 80202."
    hq_blocks = [ContentBlock(text=hq_text, block_id="b_hq", page=1)]
    hq_result = pipeline.run(hq_blocks)
    hq_replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in hq_result.entities}
    hq_sanitized = redact_text_by_values(hq_text, hq_replacements)

    assert "Optiv headquarters" in hq_sanitized
    assert "Denver" not in hq_sanitized
    assert "[REDACTED_ADDRESS]" in hq_sanitized


# =============================================================================
# Defect Category 4: Field Labels & Structural Elements
# =============================================================================

def test_defect_4_field_labels_and_structure(pipeline):
    """
    Defect Category 4:
    Field labels and document structure elements ('Condition:', 'Trigger:',
    'Trigger Type:', 'Trigger Name:', 'Rule Name', 'Email ID', 'Vendor Tier attribute',
    'Appendix A' through 'Appendix E', 'QA Reviewer') must stay unredacted and never be
    replaced with [REDACTED_PERSON].
    """
    text = (
        "Rule Configuration:\n"
        "Condition: Trigger Type: Automated. Trigger: Active.\n"
        "Trigger Name: High Risk Assessment. Rule Name: Tier 1 Rule.\n"
        "Email ID of vendor contact is required.\n"
        "Vendor Tier attribute is set to Tier 2.\n"
        "Appendix A: System Overview.\n"
        "Appendix B: TPRM Scope.\n"
        "Appendix C. Evaluation Criteria.\n"
        "Appendix D: Technical Controls.\n"
        "Appendix E: Committee Sign-off.\n"
        "QA Reviewer: Alex Mercer."
    )
    blocks = [ContentBlock(text=text, block_id="b_struct", page=1)]
    result = pipeline.run(blocks)

    # Alex Mercer should be detected, but labels and appendices must NOT
    person_vals = {e.value.strip().lower() for e in result.entities if e.entity_type == EntityType.PERSON}
    assert "alex mercer" in person_vals, "Authentic reviewer name 'Alex Mercer' was missed!"

    forbidden_labels = [
        "condition:", "condition", "trigger:", "trigger", "trigger type:", "trigger name:",
        "rule name", "email id", "vendor tier attribute",
        "appendix a", "appendix b", "appendix c", "appendix c.", "appendix d", "appendix e",
        "qa reviewer", "qa reviewer:",
    ]
    for label in forbidden_labels:
        assert label not in person_vals, f"Field label/appendix '{label}' was misclassified as PERSON!"

    replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in result.entities}
    sanitized = redact_text_by_values(text, replacements)

    assert "Condition:" in sanitized
    assert "Trigger Type:" in sanitized
    assert "Trigger Name:" in sanitized
    assert "Rule Name:" in sanitized
    assert "Email ID" in sanitized
    assert "Vendor Tier attribute" in sanitized
    assert "Appendix A:" in sanitized
    assert "Appendix B:" in sanitized
    assert "Appendix C. Evaluation Criteria." in sanitized
    assert "Appendix D:" in sanitized
    assert "Appendix E:" in sanitized
    assert "QA Reviewer: [REDACTED_PERSON]." in sanitized
    assert "[REDACTED_PERSON] A" not in sanitized
    assert "[REDACTED_PERSON] C." not in sanitized


# =============================================================================
# Defect Category 5: Ordinary Vocabulary
# =============================================================================

def test_defect_5_ordinary_words_unredacted(pipeline):
    """
    Defect Category 5:
    Common vocabulary words ('Admin', 'custom', 'templates', 'trigger', 'description',
    'Artificial Intelligence', 'Security Team', 'Launch', 'Email', 'annual',
    'Tier 3 third parties') must never be mislabeled as PII.
    """
    text = (
        "Admin must verify custom templates before launch. "
        "Launch the workflow trigger and record the description. "
        "Artificial Intelligence applications are governed by the Security Team. "
        "Email alerts trigger an annual review. "
        "Tier 3 third parties are exempt from comprehensive audits.\n"
        "Trigger: Automated workflow execution.\n"
        "Condition: Status check.\n"
        "Admin: Global configuration.\n"
        "Templates: Predefined questionnaires."
    )
    blocks = [ContentBlock(text=text, block_id="b_vocab", page=1)]
    result = pipeline.run(blocks)

    flagged_lower = {e.value.strip().lower() for e in result.entities}
    forbidden_words = [
        "admin", "custom", "templates", "trigger", "description",
        "artificial intelligence", "security team", "launch",
        "email", "annual", "tier 3 third parties", "tier 3",
        "condition",
    ]
    for word in forbidden_words:
        assert word not in flagged_lower, f"Ordinary term '{word}' was incorrectly flagged as PII!"

    replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in result.entities}
    sanitized = redact_text_by_values(text, replacements)
    assert "[REDACTED_PERSON] parties" not in sanitized
    assert "Tier 3 third parties" in sanitized
    assert "Admin" in sanitized
    assert "Launch" in sanitized
    assert "Trigger" in sanitized


# =============================================================================
# Defect Category 6: Group and Approver Names
# =============================================================================

def test_defect_6_group_and_approver_names(pipeline):
    """
    Defect Category 6:
    Group/approver names such as 'Vendor Risk Management Group',
    'Information Security Committee', 'Enterprise Risk Committee',
    'Vendor Governance Board', and 'Incident Response Team' must remain unredacted
    and never be mislabeled as individual PERSON entities.
    """
    body_text = (
        "The Vendor Risk Management Group approved the vendor exception. "
        "Escalations are reviewed by the Information Security Committee and Enterprise Risk Committee. "
        "The Vendor Governance Board and Incident Response Team confirmed the remediation plan."
    )
    blocks = [ContentBlock(text=body_text, block_id="b_groups", page=1)]
    result = pipeline.run(blocks)

    person_entities = [e.value.lower() for e in result.entities if e.entity_type == EntityType.PERSON]
    group_names = [
        "vendor risk management group",
        "information security committee",
        "enterprise risk committee",
        "vendor governance board",
        "incident response team",
    ]
    for group in group_names:
        assert group not in person_entities, f"Group '{group}' was misclassified as individual PERSON!"

    replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in result.entities}
    sanitized = redact_text_by_values(body_text, replacements)
    assert sanitized == body_text

    # Document test with Table context (approver column)
    doc = CanonicalDocument(
        doc_id="test_group_approver_doc",
        source_path="approver.docx",
        filename="approver.docx",
        file_type=".docx",
        pages=1,
        pages_dict={
            1: ExtractedPage(
                page_num=1,
                tables=[
                    ExtractedTable(
                        table_index=1,
                        page=1,
                        headers=["Control Area", "Approver"],
                        rows=[
                            [
                                TableCell(row_idx=1, col_idx=0, text="Cloud Security"),
                                TableCell(row_idx=1, col_idx=1, text="Vendor Risk Management Group", header_name="Approver"),
                            ],
                            [
                                TableCell(row_idx=2, col_idx=0, text="Risk Exception"),
                                TableCell(row_idx=2, col_idx=1, text="Information Security Committee", header_name="Approver"),
                            ],
                            [
                                TableCell(row_idx=3, col_idx=0, text="Technical Lead"),
                                TableCell(row_idx=3, col_idx=1, text="Jonathan Edwards", header_name="Approver"),
                            ],
                        ],
                    )
                ]
            )
        }
    )
    processed_doc = pipeline.run_document(doc)
    doc_persons = [e.context.get("raw_value", "") for e in processed_doc.entities if e.type == "PERSON"]

    assert any("Jonathan Edwards" in p for p in doc_persons), "Human approver 'Jonathan Edwards' must be detected!"
    for group in ["Vendor Risk Management Group", "Information Security Committee"]:
        assert not any(group in p for p in doc_persons), (
            f"Group approver '{group}' was misclassified as PERSON in table!"
        )


# =============================================================================
# Defect Category 7: Multi-Modal Token Safety & Nesting Prevention
# =============================================================================

def test_defect_7_token_safety_and_nesting_prevention():
    """
    Defect Category 7:
    Redaction operations must strictly avoid substring collisions and recursive
    token corruption (e.g., '[REDACTED:EM[REDACTED:ADDRESS]L]'). Existing redaction tokens
    and overlapping keys must be handled safely.
    """
    # 1. Direct token nesting test on redact_text_by_values
    corrupted_pattern = re.compile(r"\[REDACTED[^\]]*\[REDACTED")

    text_with_existing_token = "Notification sent to [REDACTED_EMAIL] for verification."
    replacements = {
        "EMAIL": "[REDACTED_EMAIL]",
        "AI": "[REDACTED_ORG]",
        "EM": "[REDACTED_CODE]",
        "ADDRESS": "[REDACTED_ADDR]",
    }
    sanitized = redact_text_by_values(text_with_existing_token, replacements)
    assert not corrupted_pattern.search(sanitized), f"Found nested token corruption in: {sanitized}"
    assert "[REDACTED:EM[REDACTED:ADDRESS]L]" not in sanitized
    assert "[REDACTED_EMAIL]" in sanitized

    # 2. Substring inside regular words must not collide
    sentence = "The EMAIL gateway uses AI systems."
    sanitized_sentence = redact_text_by_values(sentence, {"AI": "[REDACTED_AI]"})
    assert sanitized_sentence == "The EMAIL gateway uses [REDACTED_AI] systems."
    assert "EM[REDACTED_AI]L" not in sanitized_sentence

    # 3. PPTX slide simulation: Executive titles and names
    pptx_text = (
        "Organization at a Glance\n"
        "CADENCE FINANCIAL GROUP\n"
        "Cadence Financial Group is organised into five reporting divisions under the Chief Executive Officer.\n"
        "Governance of technology, data and risk activity is distributed across the Technology & Data and "
        "Risk, Compliance & Security divisions.\n"
        "Office of the CEO\n"
        "Strategy, communications and board reporting\n"
        "Led by Marguerite Vossberg\n"
        "Operations\n"
        "Client servicing, payments and shared services\n"
        "Led by Desmond Achterberg\n"
        "Finance\n"
        "Treasury, financial control and planning\n"
        "Technology & Data\n"
        "Engineering, infrastructure, data and security\n"
        "Led by Tobias Lindqvist\n"
    )

    names_to_redact = {
        "Marguerite Vossberg": "[REDACTED_PERSON]",
        "Desmond Achterberg": "[REDACTED_PERSON]",
        "Tobias Lindqvist": "[REDACTED_PERSON]",
    }
    sanitized_pptx = redact_text_by_values(pptx_text, names_to_redact)

    assert "Chief Executive Officer" in sanitized_pptx
    assert "Office of the CEO" in sanitized_pptx
    assert "Operations" in sanitized_pptx
    assert "Finance" in sanitized_pptx
    assert "Technology & Data" in sanitized_pptx
    assert "Marguerite Vossberg" not in sanitized_pptx
    assert "Desmond Achterberg" not in sanitized_pptx
    assert "Tobias Lindqvist" not in sanitized_pptx
    assert not corrupted_pattern.search(sanitized_pptx), f"Corrupted token in PPTX text: {sanitized_pptx}"
    assert "[REDACTED:EM[REDACTED:ADDRESS]L]" not in sanitized_pptx


# =============================================================================
# Adversarial Evasion & Multi-Modal Golden Document Cases
# =============================================================================

def test_adversarial_evasion_and_edge_cases(pipeline, policy_engine):
    """
    Adversarial Evasion & Edge Cases:
    1. Casing variations on non-PII terms ('approved', 'APPROVED', 'uNiTeD sTaTeS', 'aPpEnDiX a')
       must not trigger false positive redactions.
    2. Punctuation variations ('Trigger: High-Risk', 'Condition: (Active)', 'Appendix C.')
       must not mutate labels into redaction tokens.
    3. Dense policy prose with authentic PII embedded alongside non-PII labels must
       achieve 100% true PII recall while leaving non-PII completely unredacted.
    """
    # 1. Casing & punctuation resilience
    casing_text = (
        "Status: approved. Final decision: APPROVED. "
        "Hosting outside the UNITED STATES is permitted. "
        "Refer to appendix a, APPENDIX B, and aPpEnDiX c. "
        "Condition: (Active). Trigger: High-Risk-Vendor."
    )
    casing_blocks = [ContentBlock(text=casing_text, block_id="b_casing", page=1)]
    casing_result = pipeline.run(casing_blocks)

    casing_flagged = {e.value.lower() for e in casing_result.entities}
    for non_pii in ["approved", "united states", "appendix a", "appendix b", "appendix c", "condition", "trigger"]:
        assert non_pii not in casing_flagged, f"Case-variant non-PII '{non_pii}' was flagged!"

    # 2. Golden Page 22 Policy Simulation: Authentic narrative prose PII
    narrative_pii_text = (
        "Cadence Group Risk Management Policy v6.0 - Section 4.2 Control Evaluation.\n"
        "Primary subject Michael R. Henderson, SSN: 293-11-4829, DOB: 11/04/1978, "
        "Passport: C8839201, PAN: ABCDE1234F, residing at 1842 Willow Tree Ln, Suite 400, Chicago, IL 60601. "
        "Risk Assessment Status: Approved by Information Security Committee."
    )
    pii_blocks = [ContentBlock(text=narrative_pii_text, block_id="b_p22", page=22)]
    pii_result = pipeline.run(pii_blocks)

    detected_values = {e.value for e in pii_result.entities}
    detected_types = {e.entity_type for e in pii_result.entities}

    # True PII must be detected
    assert "Michael R. Henderson" in detected_values or any("Henderson" in v for v in detected_values)
    assert "293-11-4829" in detected_values
    assert "11/04/1978" in detected_values or any("1978" in v for v in detected_values)
    assert "C8839201" in detected_values
    assert "ABCDE1234F" in detected_values
    assert "Chicago" in detected_values or any("Chicago" in v for v in detected_values)

    # Decision and Committee must NOT be flagged as PII
    assert "Approved" not in detected_values
    assert "Information Security Committee" not in detected_values

    # Verify sanitized output
    replacements = {e.value: f"[REDACTED_{e.entity_type.value}]" for e in pii_result.entities}
    sanitized = redact_text_by_values(narrative_pii_text, replacements)

    assert "Michael R. Henderson" not in sanitized
    assert "293-11-4829" not in sanitized
    assert "C8839201" not in sanitized
    assert "ABCDE1234F" not in sanitized
    assert "Chicago" not in sanitized

    # Policy structure and non-PII must be preserved intact
    assert "Cadence Group Risk Management Policy v6.0" in sanitized
    assert "Section 4.2 Control Evaluation" in sanitized
    assert "Risk Assessment Status: Approved" in sanitized
    assert "Information Security Committee" in sanitized

    # Zero corrupted nested tokens
    assert not re.search(r"\[REDACTED[^\]]*\[REDACTED", sanitized), f"Nested token detected: {sanitized}"
