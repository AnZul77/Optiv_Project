"""
Empirical Challenge Suite: Allow-Lists, Business Codes, OCR Degradation Variants & 4-Digit Tokens
Challenger M1-2 (Allow-List & Variant Challenger)

Verifies:
1. Business codes allow-list preservation (GRP-POL-001, GRP-POL-042, RSK-4488, RSK-9912, CTL-IAM-01, CTL-IAM-12).
2. Table header protection (Employee Name, Employee ID, Risk Code, Control ID, Reviewer, Status, etc.).
3. OCR degradation variant detection (Briqhtwell, Privanka, Valdvanathan, Emilic, and Cadence roster variants).
4. Standalone 4-digit financial numbers (7741, 2218, 8827) vs harmless numbers (years 2024, section numbers).
5. Empirical failure modes & adversarial edge cases:
   - False positive collision on parenthesized year '(2020)' on Page 4 and '(2024)'
   - Line-level 70% threshold (is_full_line) over-redaction swallowing business codes
"""

import pytest
from src.ocr.regions import (
    find_pii_spans_in_text,
    extract_word_level_pii_boxes,
)


class TestBusinessCodesAllowListPreservation:
    """Empirical verification that business codes and policy IDs are never matched or redacted."""

    @pytest.mark.parametrize("code", [
        "GRP-POL-001",
        "GRP-POL-042",
        "RSK-4488",
        "RSK-9912",
        "CTL-IAM-01",
        "CTL-IAM-12",
    ])
    def test_standalone_business_codes_return_zero_spans(self, code):
        """Exact standalone business identifiers must yield empty span lists."""
        spans = find_pii_spans_in_text(code)
        assert spans == [], f"Business code '{code}' matched as PII: {spans}"

    @pytest.mark.parametrize("code", [
        "GRP-POL-001",
        "GRP-POL-042",
        "RSK-4488",
        "RSK-9912",
        "CTL-IAM-01",
        "CTL-IAM-12",
    ])
    def test_standalone_business_codes_produce_no_redaction_boxes(self, code):
        """Extracting word-level boxes on safe business codes must produce zero bounding boxes."""
        bbox = [[100.0, 200.0], [400.0, 200.0], [400.0, 230.0], [100.0, 230.0]]
        boxes = extract_word_level_pii_boxes([(bbox, code)], img_w=1700, img_h=2200)
        assert boxes == [], f"Business code '{code}' produced unwanted bounding box: {boxes}"

    @pytest.mark.parametrize("formatted_code", [
        "(GRP-POL-001)",
        "[GRP-POL-042]",
        "RSK-4488:",
        "RSK-9912;",
        "CTL-IAM-01.",
        "CTL-IAM-12,",
        "GRP-POL-001 / RSK-4488 / CTL-IAM-01",
    ])
    def test_business_codes_with_punctuation_and_delimiters(self, formatted_code):
        """Business codes surrounded by punctuation or delimiters must not be flagged."""
        spans = find_pii_spans_in_text(formatted_code)
        assert spans == [], f"Delimited business code '{formatted_code}' matched as PII: {spans}"

    @pytest.mark.parametrize("sentence", [
        "Document reference GRP-POL-001 approved under ISO 31000",
        "Policy GRP-POL-042 establishes baseline access controls",
        "Risk category code RSK-4488 active in risk register",
        "Identified item RSK-9912 escalated to risk management committee",
        "Access management rule CTL-IAM-01 applies to all administrators",
        "Privileged access session CTL-IAM-12 logged and monitored",
        "Reference INC-2024-0012 resolved without escalation",
    ])
    def test_business_codes_in_policy_sentences(self, sentence):
        """Standard narrative policy statements containing business codes must remain unredacted."""
        spans = find_pii_spans_in_text(sentence)
        assert spans == [], f"Sentence with business code matched as PII: '{sentence}' -> {spans}"

    def test_business_codes_cooccurring_with_pii_remain_unredacted(self):
        """When business code and PII are on the same line, only PII must be boxed."""
        line = "RSK-4488 is owned by Naomi K. Osadebe"
        spans = find_pii_spans_in_text(line)
        matched_tokens = [line[s:e] for s, e in spans]
        assert "Naomi K. Osadebe" in matched_tokens or any("Osadebe" in m for m in matched_tokens)
        assert not any("RSK-4488" in m for m in matched_tokens)

        # Coordinate check: box must not cover RSK-4488 (leftmost ~200px)
        bbox = [[100.0, 500.0], [900.0, 500.0], [900.0, 530.0], [100.0, 530.0]]
        boxes = extract_word_level_pii_boxes([(bbox, line)], img_w=1700, img_h=2200)
        assert len(boxes) >= 1
        # Left edge of redaction box in pixels must be well past RSK-4488
        box_x0_px = boxes[0][0] * 1700.0
        assert box_x0_px > 300.0, f"Redaction box left edge ({box_x0_px:.1f}px) incorrectly encroached on RSK-4488"


class TestTableHeadersPreservation:
    """Empirical verification that table headers are protected from false-positive detection."""

    @pytest.mark.parametrize("header", [
        "Employee Name",
        "Employee ID",
        "Risk Code",
        "Control ID",
        "Policy Title",
        "Reviewer",
        "Status",
        "Department",
        "Business Unit",
    ])
    def test_canonical_table_headers_return_zero_spans(self, header):
        spans = find_pii_spans_in_text(header)
        assert spans == [], f"Header '{header}' matched as PII: {spans}"

    @pytest.mark.parametrize("header", [
        "EMPLOYEE NAME",
        "employee id",
        "  Status  ",
        "Policy Title\t",
        "Reviewer:",
        "Employee Name:",
        "Risk Code:",
    ])
    def test_header_casing_and_punctuation_variations(self, header):
        spans = find_pii_spans_in_text(header)
        assert spans == [], f"Header variation '{header}' matched as PII: {spans}"

    @pytest.mark.parametrize("header", [
        "Policy owner",
        "Legal reviewer",
        "Privacy reviewer",
        "STATUS",
        "ACCOUNTABLE OWNER",
        "OWNER CONTACT",
        "CATEGORY OWNER",
        "APPROVER",
        "WORKSHOP LEAD",
        "RELATIONSHIP OWNER",
        "EMPLOYEE",
        "RISK OWNER",
        "THRESHOLD OWNER",
        "INDICATOR OWNER",
        "OWNER",
        "DIVISIONAL RISK LEAD",
    ])
    def test_cadence_policy_document_table_headers(self, header):
        """Verify actual table headers occurring across the 35-page Cadence Risk Policy."""
        spans = find_pii_spans_in_text(header)
        assert spans == [], f"Cadence document header '{header}' matched as PII: {spans}"


class TestOCRDegradationVariantsRobustness:
    """Empirical verification of OCR degradation variant matching and full token coverage."""

    @pytest.mark.parametrize("name_variant,expected_substring", [
        ("Briqhtwell", "Briqhtwell"),
        ("Anthony P. Briqhtwell", "Briqhtwell"),
        ("Briqhtwell (DIR-0042)", "Briqhtwell"),
        ("briqhtwell", "briqhtwell"),
        ("BRIQHTWELL", "BRIQHTWELL"),
        ("briahtwell", "briahtwell"),
        ("briqhwwell", "briqhwwell"),
    ])
    def test_briqhtwell_ocr_variants(self, name_variant, expected_substring):
        spans = find_pii_spans_in_text(name_variant)
        assert len(spans) >= 1
        matched = " ".join(name_variant[s:e] for s, e in spans)
        assert expected_substring.lower() in matched.lower()

    @pytest.mark.parametrize("name_variant,expected_substring", [
        ("Privanka", "Privanka"),
        ("Privanka S. Raghavan", "Privanka"),
        ("chaired by Privanka S. Raghavan:", "Privanka"),
        ("privanka", "privanka"),
        ("PRIVANKA", "PRIVANKA"),
        ("aprivanza", "aprivanza"),
        ("privanza", "privanza"),
        ("priyvanka", "priyvanka"),
    ])
    def test_privanka_ocr_variants(self, name_variant, expected_substring):
        spans = find_pii_spans_in_text(name_variant)
        assert len(spans) >= 1
        matched = " ".join(name_variant[s:e] for s, e in spans)
        assert expected_substring.lower() in matched.lower()

    def test_valdvanathan_matches_entire_token_not_just_vanathan(self):
        """Ensure Valdvanathan matches the full 12-char name token rather than substring 'vanathan'."""
        text = "Senior Analyst: Valdvanathan"
        spans = find_pii_spans_in_text(text)
        assert len(spans) == 1
        matched_str = text[spans[0][0]:spans[0][1]]
        assert matched_str == "Valdvanathan", f"Expected 'Valdvanathan', got partial substring '{matched_str}'"
        assert spans[0][1] - spans[0][0] == 12

    @pytest.mark.parametrize("name_variant", [
        "valdvanathan",
        "VALDVANATHAN",
        "Sneha Valdvanathan",
        "vadvanathan",
    ])
    def test_valdvanathan_variations(self, name_variant):
        spans = find_pii_spans_in_text(name_variant)
        assert len(spans) >= 1
        matched = " ".join(name_variant[s:e] for s, e in spans)
        assert "valdvanathan" in matched.lower() or "vadvanathan" in matched.lower()

    @pytest.mark.parametrize("text,expected_tokens", [
        ("Emilic", ["Emilic"]),
        ("(305) 555-0143 and that your husband, Emilic", ["(305) 555-0143", "Emilic"]),
        ("Emilic Ramos-Vega", ["Emilic Ramos-Vega"]),
        ("emilic", ["emilic"]),
        ("EMILIC", ["EMILIC"]),
        ("emilio ramos-vega", ["emilio ramos-vega"]),
    ])
    def test_emilic_cross_box_and_spelling_variants(self, text, expected_tokens):
        spans = find_pii_spans_in_text(text)
        matched = [text[s:e] for s, e in spans]
        for exp in expected_tokens:
            assert any(exp.lower() in m.lower() for m in matched), f"'{exp}' not found in matched {matched}"

    @pytest.mark.parametrize("degraded_line,expected_entity", [
        ("tohias kindavisi", "kindavisi"),
        ("ttobias kinoovist", "kinoovist"),
        ("tobias lindovist", "lindovist"),
        ("delphine okonic", "okonic"),
        ("rasalnc achlerberg", "achlerberg"),
        ("helena vorsiermann", "vorsiermann"),
        ("pohan deshmmkh", "deshmmkh"),
        ("devansh kuiarni", "kuiarni"),
        ("dunesni", "dunesni"),
        ("kansien ohiendom", "ohiendom"),
        ("maicus tvillev", "tvillev"),
    ])
    def test_extended_cadence_degradation_roster(self, degraded_line, expected_entity):
        """Verify OCR degradation catalog across Cadence personnel roster."""
        spans = find_pii_spans_in_text(degraded_line)
        assert len(spans) >= 1
        matched_text = " ".join(degraded_line[s:e] for s, e in spans).lower()
        assert expected_entity.lower() in matched_text

    @pytest.mark.parametrize("variant_text", [
        "Briqhtwell",
        "Privanka",
        "Valdvanathan",
        "Emilic",
    ])
    def test_variants_produce_valid_padded_bounding_boxes(self, variant_text):
        """Bounding box generation for degradation variants enforces scale and padding."""
        bbox = [[200.0, 300.0], [500.0, 300.0], [500.0, 340.0], [200.0, 340.0]]
        boxes = extract_word_level_pii_boxes([(bbox, variant_text)], img_w=1700, img_h=2200)
        assert len(boxes) == 1
        b = boxes[0]
        # Must be valid normalized bounds
        assert 0.0 <= b[0] < b[2] <= 1.0
        assert 0.0 <= b[1] < b[3] <= 1.0
        # Padding safety: pixel box must extend past raw box by at least 5px
        px_x0 = b[0] * 1700.0
        px_x1 = b[2] * 1700.0
        assert px_x0 <= 200.0 - 5.0 + 1e-4
        assert px_x1 >= 500.0 + 5.0 - 1e-4


class TestFinancialTokensVsHarmlessNumbers:
    """Empirical verification distinguishing sensitive financial tokens from harmless numbers."""

    @pytest.mark.parametrize("token", ["7741", "2218", "8827"])
    def test_standalone_sensitive_financial_tokens_detected(self, token):
        """Page 23 account tokens and last-4 identifiers must be matched standalone."""
        spans = find_pii_spans_in_text(token)
        assert len(spans) == 1
        assert token[spans[0][0]:spans[0][1]] == token

    @pytest.mark.parametrize("phrase", [
        "card ending 2218",
        "savings account ending 7741",
        "checking ending 7741",
        "SSN last 4 digits (8827)",
        "ending 2218",
    ])
    def test_contextual_financial_phrases_detected(self, phrase):
        spans = find_pii_spans_in_text(phrase)
        assert len(spans) >= 1

    @pytest.mark.parametrize("safe_year", [
        "2024",
        "2025",
        "2026",
        "2023",
        "2020",
        "1999",
    ])
    def test_standalone_years_not_detected_as_pii(self, safe_year):
        """Unparenthesized years must never be detected as PII."""
        spans = find_pii_spans_in_text(safe_year)
        assert spans == [], f"Standalone year '{safe_year}' matched as PII: {spans}"

    @pytest.mark.parametrize("section_text", [
        "Section 2024",
        "Section 4.1.2",
        "Rule 1004",
        "Page 2024",
        "Clause 1004",
        "ISO 31000:2018",
        "1 July 2024",
        "In year 2024, the policy was approved",
    ])
    def test_harmless_section_and_date_numbers_not_detected(self, section_text):
        """Sections, clauses, policy years, and standard references must not be flagged."""
        spans = find_pii_spans_in_text(section_text)
        assert spans == [], f"Harmless text '{section_text}' matched as PII: {spans}"


class TestAdversarialFailureModesAndVulnerabilities:
    """
    Verification that previously identified edge cases are cleanly remediated.
    """

    def test_remediation_parenthesized_year_collision_on_page_4(self):
        """
        REMEDIATION 1: Parenthesized Year False-Positive Exclusion.
        Publication years like '(2020)' on Page 4 and citation years like '(2024)'
        are excluded by negative lookahead and never flagged as PII or given redaction boxes.
        """
        spans_2020 = find_pii_spans_in_text("(2020)")
        spans_2024 = find_pii_spans_in_text("(2024)")
        assert spans_2020 == [], "Remediation verified: '(2020)' on Page 4 is not detected as PII"
        assert spans_2024 == [], "Remediation verified: '(2024)' citation is not detected as PII"

        # Verify no bounding box is emitted for harmless publication year:
        bbox = [[238.0, 367.0], [273.0, 367.0], [273.0, 380.0], [238.0, 380.0]]
        boxes = extract_word_level_pii_boxes([(bbox, "(2020)")], img_w=1700, img_h=2200)
        assert len(boxes) == 0, "Remediation verified: '(2020)' produces zero redaction boxes"

    def test_remediation_is_full_line_boundary_anchored_preserves_business_code(self):
        """
        REMEDIATION 2: Line Boundary-Anchored Full Line Redaction.
        Boundary anchoring ensures that a business code preceding an entity (e.g. 'RSK-4488')
        is never swallowed by full-line box snapping.
        """
        line = "RSK-4488 Anthony P. Brightwell"
        spans = find_pii_spans_in_text(line)
        assert spans == [(9, 30)]  # Only the name is matched

        # Line coordinates: x0=100.0, x1=500.0 (RSK-4488 is ~100..220px, name is ~230..500px)
        bbox = [[100.0, 200.0], [500.0, 200.0], [500.0, 230.0], [100.0, 230.0]]
        boxes = extract_word_level_pii_boxes([(bbox, line)], img_w=1000, img_h=1000)

        assert len(boxes) == 1
        box_x0_px = boxes[0][0] * 1000.0
        # The box must begin after RSK-4488 (> 200px):
        assert box_x0_px > 200.0, f"Remediation verified: box_x0 ({box_x0_px:.1f}px) preserved RSK-4488"
