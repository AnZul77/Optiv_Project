"""
Unit Tests: Policy Engine & Risk Model (Person 4)
=================================================

Covers config/policy.yaml loading and validation, allow-lists, effective risk
(policy can only escalate), confidence-based actions, critical dominance, and
compatibility with both entity shapes (PIIEntity / EntityAnnotation).
"""

import copy

import pytest
import yaml

from src.policy.policy import DEFAULT_POLICY_PATH, PolicyConfig, PolicyConfigError, PolicyEngine
from src.policy.risk import (
    RiskAssessment,
    inherent_risk,
    max_risk,
    normalize_risk,
    residual_risk,
    risk_exceeds,
)
from src.schema.document import EntityAnnotation
from src.schema.entities import Action, EntityType, PIIEntity, RiskLevel
from src.verification.verifier import ResidualFinding, VerificationReport


@pytest.fixture(scope="module")
def raw_policy():
    return yaml.safe_load(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def engine():
    return PolicyEngine()


def _pii(entity_type, confidence=0.95, value="x", **kw):
    return PIIEntity(entity_type=entity_type, value=value, confidence=confidence, page=1, **kw)


class TestPolicyConfig:
    def test_shipped_policy_loads(self, engine):
        cfg = engine.config
        assert cfg.version == "1.0"
        assert cfg.gate["fail_closed"] is True
        assert cfg.gate["max_allowed_residual_risk"] == "NONE"
        assert cfg.tier_for_type("SSN") == "CRITICAL"
        assert cfg.tier_for_type("ifsc") == "MEDIUM"

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(PolicyConfigError):
            PolicyConfig.load(tmp_path / "nope.yaml")

    def test_invalid_yaml_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("rules: [unclosed", encoding="utf-8")
        with pytest.raises(PolicyConfigError):
            PolicyConfig.load(bad)

    def test_fail_open_rejected(self, raw_policy):
        data = copy.deepcopy(raw_policy)
        data["gate"]["fail_closed"] = False
        with pytest.raises(PolicyConfigError, match="fail_closed"):
            PolicyConfig.from_dict(data)

    def test_allow_action_rejected_for_critical(self, raw_policy):
        data = copy.deepcopy(raw_policy)
        data["rules"]["CRITICAL"]["action"] = "ALLOW"
        with pytest.raises(PolicyConfigError):
            PolicyConfig.from_dict(data)

    def test_duplicate_entity_across_tiers_rejected(self, raw_policy):
        data = copy.deepcopy(raw_policy)
        data["rules"]["MEDIUM"]["entities"].append("SSN")
        with pytest.raises(PolicyConfigError, match="SSN"):
            PolicyConfig.from_dict(data)

    def test_bad_threshold_rejected(self, raw_policy):
        data = copy.deepcopy(raw_policy)
        data["rules"]["HIGH"]["min_confidence_to_redact"] = 1.5
        with pytest.raises(PolicyConfigError):
            PolicyConfig.from_dict(data)

    def test_bad_allow_list_regex_rejected(self, raw_policy):
        data = copy.deepcopy(raw_policy)
        data["allow_lists"]["business_codes"].append("([unclosed")
        with pytest.raises(PolicyConfigError):
            PolicyConfig.from_dict(data)

    def test_missing_sections_fall_back_to_strict_defaults(self):
        cfg = PolicyConfig.from_dict({"rules": {"CRITICAL": {"entities": ["SSN"]}}})
        assert cfg.gate["fail_closed"] is True
        assert cfg.tiers["HIGH"].action == "REDACT"
        assert cfg.redaction["mode"] == "token"


class TestAllowList:
    @pytest.mark.parametrize("code", ["INC-2026-0417", "RSK-117", "GRP-POL-001", "CTL-IAM-004"])
    def test_business_codes_allowed(self, engine, code):
        assert engine.is_allow_listed(code)

    @pytest.mark.parametrize("value", ["INC-2026-219457890", "219-45-7890", "", None, "RSK-1234567"])
    def test_non_codes_and_smuggled_digits_not_allowed(self, engine, value):
        assert not engine.is_allow_listed(value)

    def test_allow_listed_entity_gets_allow(self, engine):
        entity = _pii(EntityType.EMPLOYEE_ID, value="RSK-117")
        result = engine.apply([entity])
        assert entity.action == Action.ALLOW
        assert result.document_action == "ALLOW"
        assert result.inherent_risk == "NONE"

    def test_spans_found_in_text(self, engine):
        spans = engine.find_allow_listed_spans("See INC-2026-0417 and RSK-1.")
        assert len(spans) == 2


class TestEffectiveRisk:
    def test_policy_escalates_tax_id_to_critical(self, engine):
        assert engine.effective_risk("TAX_ID") == "CRITICAL"

    def test_policy_never_downgrades_schema_risk(self, engine):
        # Schema says HIGH for EMPLOYEE_ID; policy tier is HIGH too; detector says CRITICAL.
        assert engine.effective_risk("EMPLOYEE_ID", "CRITICAL") == "CRITICAL"
        assert engine.effective_risk("IFSC", "LOW") == "MEDIUM"

    def test_unknown_type_defaults_high(self, engine):
        assert engine.effective_risk("BIOMETRIC_TEMPLATE") == "HIGH"


class TestEntityActions:
    def test_confident_critical_is_redacted(self, engine):
        entity = _pii(EntityType.SSN, 0.92)
        result = engine.apply([entity])
        assert entity.action == Action.REDACT
        assert entity.risk_level == RiskLevel.CRITICAL
        assert result.document_action == "REDACT"
        assert result.inherent_risk == "CRITICAL"

    def test_uncertain_critical_blocks_document(self, engine):
        entity = _pii(EntityType.PASSPORT, 0.30)
        result = engine.apply([entity])
        assert entity.action == Action.BLOCK
        assert result.is_blocked
        assert "PASSPORT on page 1" in result.block_reasons[0]

    def test_uncertain_high_is_redacted_not_dropped(self, engine):
        entity = _pii(EntityType.PERSON, 0.40)
        engine.apply([entity])
        assert entity.action == Action.REDACT

    @pytest.mark.parametrize("bad", [None, "n/a", float("nan")])
    def test_bad_confidence_treated_as_uncertain(self, engine, bad):
        entity = _pii(EntityType.SSN)
        entity.confidence = bad
        assert engine.evaluate_entity(entity).action == "BLOCK"

    def test_entity_annotation_strings_updated(self, engine):
        ann = EntityAnnotation.create("TAX_ID", "12-3456789", source="regex", page=3,
                                      confidence=0.9, risk="HIGH")
        result = engine.apply([ann])
        assert ann.action == "REDACT"
        assert ann.risk == "CRITICAL"
        assert ann.context["policy"]["allow_listed"] is False
        assert result.decisions[0].entity_type == "TAX_ID"

    def test_raw_values_enable_allow_list_for_annotations(self, engine):
        ann = EntityAnnotation.create("EMPLOYEE_ID", "INC-2026-0417", source="regex", page=1)
        engine.apply([ann], raw_values={ann.entity_id: "INC-2026-0417"})
        assert ann.action == "ALLOW"

    def test_no_entities_means_allow(self, engine):
        result = engine.apply([])
        assert result.document_action == "ALLOW"
        assert result.inherent_risk == "NONE"

    def test_decisions_contain_no_raw_values(self, engine):
        entity = _pii(EntityType.SSN, value="219-45-7890")
        result = engine.apply([entity])
        assert "219-45-7890" not in str(result.to_dict())

    def test_apply_to_document(self, engine):
        from src.schema.document import CanonicalDocument
        doc = CanonicalDocument(doc_id="d1", source_path="x", filename="x.pdf", file_type=".pdf", pages=1)
        doc.entities = [EntityAnnotation.create("SSN", "219-45-7890", source="regex", page=1, confidence=0.9)]
        result = engine.apply_to_document(doc)
        assert result.document_action == "REDACT"
        assert doc.metadata["policy_summary"]["inherent_risk"] == "CRITICAL"


class TestRiskModel:
    def test_normalize(self):
        assert normalize_risk(RiskLevel.CRITICAL) == "CRITICAL"
        assert normalize_risk("medium") == "MEDIUM"
        assert normalize_risk("weird") == "HIGH"
        assert normalize_risk(None) == "HIGH"

    def test_critical_dominance(self):
        assert max_risk(["LOW", "MEDIUM", "CRITICAL", "HIGH"]) == "CRITICAL"
        assert max_risk([]) == "NONE"
        assert risk_exceeds("LOW", "NONE")
        assert not risk_exceeds("NONE", "NONE")

    def test_inherent_ignores_allow_listed(self):
        ssn = _pii(EntityType.SSN, action=Action.ALLOW)
        email = _pii(EntityType.EMAIL)
        assert inherent_risk([ssn, email]) == "HIGH"

    def test_residual_none_when_redacted_and_verified(self):
        assert residual_risk([_pii(EntityType.SSN)], VerificationReport(units_scanned=1)) == "NONE"

    def test_residual_critical_without_verification(self):
        assert residual_risk([_pii(EntityType.EMAIL)], None) == "CRITICAL"

    def test_residual_counts_unapplied_and_findings(self):
        email = _pii(EntityType.EMAIL)
        assert residual_risk([email], VerificationReport(units_scanned=1),
                             unapplied_entity_ids=[email.entity_id]) == "HIGH"
        finding = ResidualFinding("IFSC", "MEDIUM", "x", 1, "b", "block", 0, 4, "h", 0.8)
        assert residual_risk([], VerificationReport(findings=[finding], units_scanned=1)) == "MEDIUM"

    def test_risk_assessment(self):
        assessment = RiskAssessment.assess([_pii(EntityType.SSN), _pii(EntityType.EMAIL)],
                                           VerificationReport(units_scanned=1))
        assert assessment.to_dict()["inherent_risk"] == "CRITICAL"
        assert assessment.residual == "NONE"
        assert assessment.entity_counts == {"CRITICAL": 1, "HIGH": 1}
