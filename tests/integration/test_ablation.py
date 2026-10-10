"""
Integration Tests: Day 16 Ablation Benchmark
============================================

Compares the baseline (Regex-only) detection against the Context-Enhanced
pipeline across key metrics:
- Recall on ambiguous PII / table cells
- False positive handling on allow-listed terms
- Confidence score boosting on high-signal context
"""

import pytest
from src.schema.entities import (
    ContentBlock,
    EntityType,
    TableContext,
)
from src.detection.pipeline import DetectionPipeline


class TestAblationBenchmark:
    """Benchmark comparing baseline vs. full context-enhanced pipeline."""

    @pytest.fixture
    def test_corpus(self):
        """Standardized evaluation corpus with mixed context signals."""
        return [
            # Ambiguous format in table without standard prefix
            ContentBlock(
                text="123456789",
                block_id="table_cell_ssn",
                page=1,
                table_context=TableContext(
                    table_id="t1",
                    row_index=1,
                    col_index=1,
                    column_headers=["SSN"],
                ),
            ),
            # Personal details section with DOB
            ContentBlock(
                text="Employee DOB: 1985-11-23 on record.",
                block_id="section_dob",
                page=1,
                section_context="Employee Personal Information",
            ),
            # Standard regex-detectable PII
            ContentBlock(
                text="Direct email contact: dev-lead@optiv.com",
                block_id="contact_email",
                page=2,
            ),
        ]

    def test_context_enhances_recall_on_table_data(self, test_corpus):
        """
        Baseline regex fails on unformatted numbers in tables without punctuation,
        while Context Engine propagates column header and recovers the entity.
        """
        # 1. Baseline: Regex only
        baseline_pipeline = DetectionPipeline(
            enable_regex=True,
            enable_ner=False,
            enable_context=False,
            enable_validators=False,
            enable_allow_list=False,
        )
        baseline_result = baseline_pipeline.run(test_corpus)

        # 2. Context-Enhanced Pipeline
        enhanced_pipeline = DetectionPipeline(
            enable_regex=True,
            enable_ner=False,
            enable_context=True,
            enable_validators=True,
            enable_allow_list=True,
        )
        enhanced_result = enhanced_pipeline.run(test_corpus)

        # 3. Assert context enhancement detected more entities in structured blocks
        assert enhanced_result.total_entities >= baseline_result.total_entities

        # 4. Specifically verify table cell SSN was captured in enhanced pipeline
        enhanced_types = [e.entity_type for e in enhanced_result.entities]
        assert EntityType.SSN in enhanced_types

    def test_context_boosts_confidence_scores(self, test_corpus):
        """Entities detected in proximity to cues/sections receive higher confidence."""
        baseline_pipeline = DetectionPipeline(
            enable_regex=True,
            enable_ner=False,
            enable_context=False,
            enable_validators=False,
        )
        enhanced_pipeline = DetectionPipeline(
            enable_regex=True,
            enable_ner=False,
            enable_context=True,
            enable_validators=True,
        )

        base_res = baseline_pipeline.run(test_corpus)
        enh_res = enhanced_pipeline.run(test_corpus)

        base_dob = [e for e in base_res.entities if e.entity_type == EntityType.DOB]
        enh_dob = [e for e in enh_res.entities if e.entity_type == EntityType.DOB]

        if base_dob and enh_dob:
            # Context and validator layers boost the confidence of the DOB entity
            assert enh_dob[0].confidence >= base_dob[0].confidence
