"""
Integration Tests: End-to-End PII Detection Pipeline
=====================================================

Simulates realistic multi-page enterprise document processing with:
- Page 1: Mixed international PII (SSN, PAN, Email, Phone) + Allow-listed codes
- Page 2: Table structures with column header propagation
- Page 3: Structured KYC section with Aadhaar and DOB

Verifies:
- Layer orchestration (Regex -> Context -> Validator -> Resolver)
- Non-PII suppression (Allow-list)
- Risk classification & summary accuracy
- Fail-closed metadata tracking
"""

import pytest
from src.schema.entities import (
    ContentBlock,
    EntityType,
    RiskLevel,
    TableContext,
    ValidatorStatus,
)
from src.detection.pipeline import DetectionPipeline


@pytest.fixture
def full_pipeline():
    """Pipeline configured for end-to-end testing."""
    return DetectionPipeline(
        enable_regex=True,
        enable_ner=False,  # Keep fast and deterministic for test runs
        enable_context=True,
        enable_validators=True,
        enable_allow_list=True,
    )


class TestEndToEndPipeline:
    """End-to-end document processing tests."""

    def test_multipage_enterprise_document(self, full_pipeline):
        # 1. Prepare multi-page document blocks
        blocks = [
            # Page 1: Executive Summary & Contact (Prose + Allow-list items)
            ContentBlock(
                text=(
                    "Executive Summary for Audit INC-2024-089 and ISO-27001 Compliance. "
                    "Primary point of contact is Alice Walker at alice.walker@optiv-security.com "
                    "or reach via mobile +1 (415) 555-2671. US Tax SSN: 219-45-7890."
                ),
                block_id="p1_summary",
                page=1,
                section_context="Executive Summary",
            ),
            ContentBlock(
                text="Regional Director PAN: ABCPE1234F verified by compliance team.",
                block_id="p1_pan",
                page=1,
                section_context="Tax Compliance",
            ),

            # Page 2: Financial & Employee Table
            ContentBlock(
                text="4000123456789010",
                block_id="p2_tbl_row1_c1",
                page=2,
                table_context=TableContext(
                    table_id="tbl_payroll",
                    row_index=1,
                    col_index=1,
                    column_headers=["Corporate Credit Card"],
                ),
            ),
            ContentBlock(
                text="EMP-908234",
                block_id="p2_tbl_row1_c2",
                page=2,
                table_context=TableContext(
                    table_id="tbl_payroll",
                    row_index=1,
                    col_index=2,
                    column_headers=["Staff ID"],
                ),
            ),

            # Page 3: KYC & Personal Details Section + Bank IFSC
            ContentBlock(
                text="Aadhaar UID: 2345 6789 0123. Date of Birth: 14/07/1988. Bank IFSC: SBIN0001234.",
                block_id="p3_kyc",
                page=3,
                section_context="Identity Verification and KYC Details",
            ),
        ]

        # 2. Run Pipeline
        result = full_pipeline.run(
            blocks=blocks,
            source_file="Optiv_Q3_Compliance_Report.pdf",
            document_id="doc_optiv_9081",
        )

        # 3. Assertions on Document-Level Metrics
        assert result.document_id == "doc_optiv_9081"
        assert result.source_file == "Optiv_Q3_Compliance_Report.pdf"
        assert result.detection_metadata.blocks_processed == 5
        assert result.detection_metadata.pages_processed == 3
        assert result.detection_metadata.processing_time_ms > 0

        # 4. Verify Detected Entity Types
        detected_types = {e.entity_type for e in result.entities}
        assert EntityType.EMAIL in detected_types
        assert EntityType.PHONE in detected_types
        assert EntityType.SSN in detected_types
        assert EntityType.PAN in detected_types
        assert EntityType.CARD in detected_types
        assert EntityType.AADHAAR in detected_types
        assert EntityType.DOB in detected_types
        assert EntityType.IFSC in detected_types

        # 5. Verify Allow-list Suppression
        # "INC-2024-089" and "ISO-27001" must NOT be extracted as PII
        detected_values = [e.value for e in result.entities]
        for val in detected_values:
            assert "INC-2024-089" not in val
            assert "ISO-27001" not in val

        # 6. Verify Risk Level Breakdown
        assert result.risk_summary.get("CRITICAL", 0) >= 3  # SSN, PAN, Card, Aadhaar
        assert result.risk_summary.get("HIGH", 0) >= 2      # Email, Phone, DOB, Employee ID
        assert result.risk_summary.get("MEDIUM", 0) >= 1    # IFSC

        # 7. Verify Validator Enrichments
        pan_entity = [e for e in result.entities if e.entity_type == EntityType.PAN][0]
        assert pan_entity.validator_result == ValidatorStatus.PASS
        assert "validator" in pan_entity.detection_layers

        ssn_entity = [e for e in result.entities if e.entity_type == EntityType.SSN][0]
        assert ssn_entity.validator_result == ValidatorStatus.PASS

    def test_canonical_document_direct_integration(self, full_pipeline):
        """Test DetectionPipeline.run_document() on Person 1's CanonicalDocument."""
        from src.schema.document import CanonicalDocument, ExtractedPage, ExtractedBlock, ExtractedTable, TableCell

        doc = CanonicalDocument(
            doc_id="test_doc_001",
            source_path="report.pdf",
            filename="report.pdf",
            file_type=".pdf",
            pages=1,
            pages_dict={
                1: ExtractedPage(
                    page_num=1,
                    blocks=[
                        ExtractedBlock(
                            block_id="b1",
                            page=1,
                            block_type="paragraph",
                            text="Primary contact: lead@optiv.com, SSN: 123-45-6789.",
                        )
                    ],
                    tables=[
                        ExtractedTable(
                            table_index=1,
                            page=1,
                            headers=["Account Type", "PAN Number"],
                            rows=[
                                [
                                    TableCell(row_idx=1, col_idx=1, text="Savings"),
                                    TableCell(row_idx=1, col_idx=2, text="ABCPE1234F", header_name="PAN Number"),
                                ]
                            ]
                        )
                    ]
                )
            }
        )

        processed_doc = full_pipeline.run_document(doc)
        assert len(processed_doc.entities) >= 3
        types = {ann.type for ann in processed_doc.entities}
        assert "EMAIL" in types
        assert "SSN" in types
        assert "PAN" in types
        assert "detection_summary" in processed_doc.metadata

