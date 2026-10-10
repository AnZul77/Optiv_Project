"""
Unit Tests: Relational Privacy Engine (src/policy/relational.py)
==============================================================
Tests contextual integrity, dependency parsing, and action triple sensitivity.
"""

import pytest
from src.policy.relational import RelationalPrivacyEngine


@pytest.fixture(scope="module")
def engine():
    return RelationalPrivacyEngine()


def test_public_literary_fact_preserved(engine):
    sent = "J.K. Rowling wrote Harry Potter in 1997."
    res = engine.assess_entity_in_sentence(sent, "J.K. Rowling", entity_type="PERSON")
    assert not res.is_sensitive
    assert res.linkability_score < 0.25
    assert "Public informational predicate" in res.reason


def test_scientific_discovery_fact_preserved(engine):
    sent = "Albert Einstein published the general theory of relativity."
    res = engine.assess_entity_in_sentence(sent, "Albert Einstein", entity_type="PERSON")
    assert not res.is_sensitive
    assert res.linkability_score < 0.25


def test_financial_transfer_redacted(engine):
    sent = "Anshul transferred $10k to Optiv on Friday."
    res = engine.assess_entity_in_sentence(sent, "Anshul", entity_type="PERSON")
    assert res.is_sensitive
    assert res.linkability_score >= 0.85
    assert "Coupled with sensitive anchors" in res.reason or "Sensitive action" in res.reason


def test_compensation_salary_redacted(engine):
    sent = "Desmond Achterberg earned an annual bonus of $50,000."
    res = engine.assess_entity_in_sentence(sent, "Desmond Achterberg", entity_type="PERSON")
    assert res.is_sensitive
    assert res.linkability_score >= 0.85


def test_corporate_description_not_sensitive(engine):
    sent = "Optiv is the cyber advisory and solutions leader delivering strategic cybersecurity."
    res = engine.assess_entity_in_sentence(sent, "Optiv", entity_type="PERSON")
    assert not res.is_sensitive
    assert res.linkability_score < 0.30


def test_inherently_sensitive_types_always_flagged(engine):
    sent = "His SSN is 123-45-6789 on the document."
    res = engine.assess_entity_in_sentence(sent, "123-45-6789", entity_type="SSN")
    assert res.is_sensitive
    assert res.linkability_score >= 0.90
