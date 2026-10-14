"""
Integration Tests: Day 18 LLM Utility & Output Security Evaluation Suite
========================================================================

Verifies:
1. Standardized 20-Question Dataset integrity (10 Operational, 10 PII-targeted).
2. Information Utility Retention >= 80% across operational questions.
3. Zero PII Leakage Rate (0.0%) across PII-targeted questions.
4. Redaction token integrity ([REDACTED_...] applied, raw PII omitted).
5. Robust detection of simulated leaks and degradation.
"""

import pytest
from src.evaluation.llm_utility import (
    CADENCE_EVALUATION_DATASET_20_QA,
    EvaluationQuestion,
    LLMUtilityEvaluator,
    QuestionType,
    run_llm_utility_benchmark,
)
from src.evaluation.utility import (
    ENTERPRISE_UTILITY_BENCHMARK_20_QA,
    BenchmarkDomain,
    EnterpriseUtilityEvaluator,
    EnterpriseUtilityReport,
    UtilityTestCase,
    run_utility_evaluation,
)


class TestLLMUtilitySuite:
    """Test suite for Day 18 LLM Utility Evaluation."""

    def test_standardized_20_question_dataset_integrity(self):
        """Verify the evaluation dataset contains exactly 20 standardized questions."""
        dataset = CADENCE_EVALUATION_DATASET_20_QA
        assert len(dataset) == 20, f"Expected exactly 20 questions, found {len(dataset)}"

        op_questions = [q for q in dataset if q.question_type == QuestionType.OPERATIONAL]
        pii_questions = [q for q in dataset if q.question_type == QuestionType.PII_TARGETED]

        assert len(op_questions) == 10, f"Expected 10 operational questions, got {len(op_questions)}"
        assert len(pii_questions) == 10, f"Expected 10 PII-targeted questions, got {len(pii_questions)}"

        # Verify operational questions have expected domains and keywords
        for op_q in op_questions:
            assert op_q.domain, f"Missing domain for {op_q.id}"
            assert len(op_q.expected_operational_keywords) >= 2, f"Insufficient keywords for {op_q.id}"
            assert op_q.canonical_answer_original, f"Missing original answer for {op_q.id}"
            assert op_q.canonical_answer_sanitized, f"Missing sanitized answer for {op_q.id}"

        # Verify PII questions have target types, raw values, and redaction tokens
        for pii_q in pii_questions:
            assert pii_q.target_pii_type in {
                "EMAIL", "PHONE", "SSN", "DOB", "PASSPORT", "PAN", "ADDRESS", "EMPLOYEE_ID", "DIRECTOR_ID"
            }, f"Unexpected target PII type {pii_q.target_pii_type} for {pii_q.id}"
            assert pii_q.raw_pii_value, f"Missing raw PII value for {pii_q.id}"
            assert pii_q.expected_redaction_token, f"Missing redaction token for {pii_q.id}"
            assert pii_q.expected_redaction_token.startswith("[REDACTED_")

    def test_cadence_reference_utility_benchmark_passes(self):
        """Verify the full Day 18 benchmark satisfies retention >= 80% and leakage == 0.0%."""
        report = run_llm_utility_benchmark()

        assert report.total_questions == 20
        assert report.operational_questions_count == 10
        assert report.pii_questions_count == 10

        # Information utility retention must be >= 80%
        assert report.information_utility_retention >= 0.80, (
            f"Utility retention fell below 80%: {report.information_utility_retention:.1%}"
        )
        assert report.sanitized_operational_accuracy >= 0.80

        # PII leakage must be strictly zero (0.0%)
        assert report.pii_leakage_rate == 0.0, (
            f"Zero-tolerance violated! PII leakage detected: {report.pii_leakage_rate:.1%}"
        )

        assert report.passed is True

    def test_operational_answer_accuracy_preservation(self):
        """Verify operational questions maintain accuracy between original and sanitized documents."""
        evaluator = LLMUtilityEvaluator()
        report = evaluator.run_suite()

        op_results = [r for r in report.results if r.question_type == QuestionType.OPERATIONAL]
        assert len(op_results) == 10

        for res in op_results:
            assert res.passed is True
            assert res.operational_accuracy_sanitized >= 0.80
            assert res.pii_leaked_sanitized is False

    def test_zero_pii_leakage_and_redaction_token_replacement(self):
        """Verify that sanitized responses return [REDACTED_...] and zero raw PII."""
        evaluator = LLMUtilityEvaluator()
        report = evaluator.run_suite()

        pii_results = [r for r in report.results if r.question_type == QuestionType.PII_TARGETED]
        assert len(pii_results) == 10

        for res in pii_results:
            assert res.passed is True
            assert res.pii_leaked_sanitized is False
            assert res.redaction_token_present is True
            assert "[REDACTED_" in res.sanitized_answer

            # Raw PII must NOT appear in sanitized answer
            matching_q = next(q for q in CADENCE_EVALUATION_DATASET_20_QA if q.id == res.question_id)
            assert matching_q.raw_pii_value not in res.sanitized_answer

    def test_original_context_reveals_raw_pii(self):
        """Verify that unredacted original context indeed contains the targeted PII."""
        evaluator = LLMUtilityEvaluator()
        report = evaluator.run_suite()

        pii_results = [r for r in report.results if r.question_type == QuestionType.PII_TARGETED]
        for res in pii_results:
            matching_q = next(q for q in CADENCE_EVALUATION_DATASET_20_QA if q.id == res.question_id)
            assert matching_q.raw_pii_value in res.original_answer

    def test_simulated_pii_leakage_trips_failure(self):
        """Verify that any leaked PII entity trips the suite and sets passed = False."""
        evaluator = LLMUtilityEvaluator()

        # Simulate a faulty LLM that leaks an SSN in response to PII-03
        def faulty_qa_fn(q: EvaluationQuestion, is_sanitized: bool) -> str:
            if q.id == "PII-03" and is_sanitized:
                return "The Social Security Number is 293-11-4829."  # LEAK!
            if is_sanitized:
                return q.canonical_answer_sanitized
            return q.canonical_answer_original

        report = evaluator.run_suite(custom_qa_fn=faulty_qa_fn)

        assert report.pii_leakage_rate > 0.0
        assert report.pii_leakage_rate == pytest.approx(0.10, abs=0.01)
        assert report.passed is False

        leaked_res = next(r for r in report.results if r.question_id == "PII-03")
        assert leaked_res.pii_leaked_sanitized is True
        assert leaked_res.passed is False

    def test_simulated_operational_degradation_trips_failure(self):
        """Verify that loss of operational content drops utility retention and fails suite."""
        evaluator = LLMUtilityEvaluator()

        # Simulate degraded answers for 4 operational questions
        def degraded_qa_fn(q: EvaluationQuestion, is_sanitized: bool) -> str:
            if is_sanitized and q.id in {"OP-01", "OP-02", "OP-03", "OP-04"}:
                return "Not available in document."  # degraded
            if is_sanitized:
                return q.canonical_answer_sanitized
            return q.canonical_answer_original

        report = evaluator.run_suite(custom_qa_fn=degraded_qa_fn)

        assert report.sanitized_operational_accuracy < 0.80
        assert report.information_utility_retention < 0.80
        assert report.passed is False

    def test_report_serialization_and_markdown(self):
        """Verify serialization to dictionary and markdown table output."""
        report = run_llm_utility_benchmark()
        rep_dict = report.to_dict()

        assert rep_dict["total_questions"] == 20
        assert rep_dict["information_utility_retention"] == 1.0
        assert rep_dict["pii_leakage_rate"] == 0.0
        assert rep_dict["passed"] is True
        assert len(rep_dict["results"]) == 20

        md_output = report.to_markdown()
        assert "# 🎯 Day 18 LLM Utility Evaluation Report" in md_output
        assert "100.0%" in md_output
        assert "0.0%" in md_output
        assert "OP-01" in md_output
        assert "PII-10" in md_output


class TestEnterpriseUtilityHarness:
    """Automated integration tests for the 20-question enterprise utility evaluation harness."""

    def test_twenty_question_benchmark_structure_and_domains(self):
        """Verify the 20 enterprise questions span all 5 specified domains (4 each)."""
        dataset = ENTERPRISE_UTILITY_BENCHMARK_20_QA
        assert len(dataset) == 20, f"Expected 20 questions, got {len(dataset)}"

        domains = {q.domain for q in dataset}
        assert len(domains) == 5, f"Expected 5 domains, got {len(domains)}"

        expected_domains = {
            BenchmarkDomain.TPRM_VENDOR_TIERING,
            BenchmarkDomain.RISK_POLICIES_CONTROLS,
            BenchmarkDomain.ORG_HIERARCHY_ESCALATION,
            BenchmarkDomain.COMPLIANCE_AUDITS_CONTROLS,
            BenchmarkDomain.ENTERPRISE_OPERATIONS,
        }
        assert domains == expected_domains

        for dom in expected_domains:
            count = sum(1 for q in dataset if q.domain == dom)
            assert count == 4, f"Expected 4 questions for domain {dom}, found {count}"

        # Verify each test case has essential fields
        for q in dataset:
            assert q.id.startswith("UTILITY-")
            assert q.prompt.strip()
            assert q.source_document.strip()
            assert len(q.expected_factual_concepts) >= 4
            assert len(q.pii_entities) >= 1
            assert q.canonical_answer_sanitized.strip()

    def test_enterprise_utility_preservation_score_meets_target(self):
        """Verify overall utility preservation score >= 95% and zero PII leaks."""
        report = run_utility_evaluation()

        assert report.total_cases == 20
        assert report.overall_utility_retention >= 0.95, (
            f"Utility preservation fell below 95%: {report.overall_utility_retention:.1%}"
        )
        assert report.overall_pii_leak_rate == 0.0, (
            f"Zero-tolerance violated! PII leakage detected: {report.overall_pii_leak_rate:.1%}"
        )
        assert report.passed is True

        # Check each domain achieves >= 95% retention
        for domain_name, score in report.domain_scores.items():
            assert score >= 0.95, f"Domain '{domain_name}' retention fell below 95%: {score:.1%}"

    def test_zero_pii_leakage_in_sanitized_contexts_and_answers(self):
        """Verify zero PII leaks in sanitized contexts and canonical answers."""
        evaluator = EnterpriseUtilityEvaluator()
        report = evaluator.run_suite()

        for res in report.results:
            assert res.is_security_passed is True
            assert res.pii_leak_count == 0
            assert len(res.pii_leaks_detected) == 0

        # Verify raw PII does NOT exist in sanitized context
        for q in ENTERPRISE_UTILITY_BENCHMARK_20_QA:
            for pii in q.pii_entities:
                assert pii.raw_value.lower() not in q.sanitized_context.lower(), (
                    f"Raw PII {pii.raw_value} leaked in sanitized context for {q.id}"
                )
                assert pii.raw_value.lower() not in q.canonical_answer_sanitized.lower(), (
                    f"Raw PII {pii.raw_value} leaked in sanitized answer for {q.id}"
                )
                assert "[REDACTED_" in q.sanitized_context, f"Missing redaction token in {q.id}"

    def test_simulated_pii_leak_trips_security_failure(self):
        """Verify that any leaked PII trips the security verification and fails the suite."""
        evaluator = EnterpriseUtilityEvaluator()

        def adversarial_leaking_qa_fn(test_case: UtilityTestCase, is_sanitized: bool) -> str:
            if test_case.id == "UTILITY-05":
                # Leak Michael Henderson's raw SSN in the response
                return "The threshold is 15 and SSN is 293-11-4829."
            return test_case.canonical_answer_sanitized

        report = evaluator.run_suite(custom_qa_fn=adversarial_leaking_qa_fn)
        assert report.overall_pii_leak_rate > 0.0
        assert report.passed is False

        leaked_res = next(r for r in report.results if r.test_id == "UTILITY-05")
        assert leaked_res.is_security_passed is False
        assert leaked_res.passed is False
        assert any("293-11-4829" in leak for leak in leaked_res.pii_leaks_detected)

    def test_simulated_factual_degradation_trips_utility_failure(self):
        """Verify that loss of required operational facts trips utility verification."""
        evaluator = EnterpriseUtilityEvaluator()

        def degraded_qa_fn(test_case: UtilityTestCase, is_sanitized: bool) -> str:
            if test_case.id in {"UTILITY-01", "UTILITY-02", "UTILITY-03"}:
                return "Information not specified in policy."
            return test_case.canonical_answer_sanitized

        # With degraded answers, test case utility retention should drop
        res = evaluator.evaluate_test_case(
            ENTERPRISE_UTILITY_BENCHMARK_20_QA[0],
            generated_answer="Unknown policy details.",
            use_sanitized=True,
        )
        assert res.utility_retention_score < 0.95
        assert res.is_utility_passed is False
        assert res.passed is False

    def test_markdown_report_generation(self):
        """Verify the evaluation report markdown file contains all required sections."""
        evaluator = EnterpriseUtilityEvaluator()
        report = evaluator.run_suite()
        md_text = report.to_markdown()

        assert "# 🎯 Enterprise LLM Utility & Security Evaluation Report" in md_text
        assert "Overall Utility Retention" in md_text
        assert "100.0%" in md_text
        assert "PII Leakage Rate" in md_text
        assert "0.0%" in md_text
        assert "TPRM Questionnaire Evaluation & Vendor Tiering" in md_text
        assert "UTILITY-01" in md_text
        assert "UTILITY-20" in md_text

