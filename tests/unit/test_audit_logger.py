"""
Unit Tests: Zero-PII Audit Logger (Person 4)
"""

import json

import pytest

from src.audit.logger import AuditLogError, AuditLogger, audit_compliance_check
from src.schema.document import EntityAnnotation
from src.schema.entities import Action, EntityType, PIIEntity
from src.verification.gate import GateDecision, GateReason
from src.verification.verifier import IndependentVerifier

SSN = "219-45-7890"
EMAIL = "alice.walker@optiv-security.com"


@pytest.fixture
def log(tmp_path):
    return AuditLogger(log_path=tmp_path / "audit.log", salt="test-salt")


@pytest.fixture
def entities():
    return [
        PIIEntity(entity_type=EntityType.SSN, value=SSN, confidence=0.93, page=22,
                  bbox=(120, 450, 310, 490), action=Action.REDACT),
        PIIEntity(entity_type=EntityType.EMAIL, value=EMAIL, confidence=0.97, page=3,
                  action=Action.REDACT),
        PIIEntity(entity_type=EntityType.EMPLOYEE_ID, value="RSK-117", confidence=0.6, page=1,
                  action=Action.ALLOW),
    ]


def _lines(log):
    return [json.loads(l) for l in log.log_path.read_text(encoding="utf-8").splitlines() if l.strip()]


def test_entity_record_matches_prd_schema(log, entities):
    log.log_entity("doc-1", "Risk_Policy_2026.pdf", entities[0], gate_decision="PASS")
    record = _lines(log)[0]
    for key in ("timestamp", "document_id", "filename", "entity_id", "type", "value_hash",
                "page", "bbox", "action", "gate_decision"):
        assert key in record
    assert record["type"] == "SSN"
    assert record["action"] == "REDACTED"
    assert record["page"] == 22
    assert record["bbox"] == [120.0, 450.0, 310.0, 490.0]
    assert record["timestamp"].endswith("Z")


def test_action_past_tense_mapping(log, entities):
    log.log_entity("d", "f.pdf", entities[2])
    assert _lines(log)[0]["action"] == "ALLOWED"


def test_log_document_writes_full_trail(log, entities):
    report = IndependentVerifier().verify_text(f"leftover {SSN}")
    decision = GateDecision("doc-9", "BLOCK", [GateReason("RESIDUAL_LEAK_DETECTED", "1 finding: SSN p.1")])
    written = log.log_document("doc-9", "/home/jsmith/secret/Policy.pdf", entities, decision,
                               verification_report=report)
    records = _lines(log)
    assert written == len(records) == 5  # 3 entities + 1 finding + 1 gate summary
    events = [r["event"] for r in records]
    assert events.count("ENTITY_DECISION") == 3
    assert events[-1] == "GATE_DECISION"
    assert all(r["gate_decision"] == "BLOCK" for r in records)
    assert all(r["filename"] == "Policy.pdf" for r in records)  # directory stripped


def test_no_raw_pii_anywhere(log, entities):
    report = IndependentVerifier().verify_text(f"leftover {SSN} and {EMAIL}")
    decision = GateDecision("doc-9", "BLOCK", [GateReason("RESIDUAL_LEAK_DETECTED", f"saw {SSN}")])
    log.log_document("doc-9", f"{EMAIL}.pdf", entities, decision, verification_report=report)
    log.log_security_event("doc-9", "x.pdf", "SIZE_LIMIT_EXCEEDED", f"uploaded by {EMAIL}")
    content = log.log_path.read_text(encoding="utf-8")
    assert SSN not in content and EMAIL not in content
    assert "[SCRUBBED:" in content
    result = audit_compliance_check(log.log_path, [SSN, EMAIL])
    assert result["compliant"], result


def test_compliance_check_flags_leaky_log(tmp_path):
    path = tmp_path / "bad.log"
    path.write_text(json.dumps({"event": "X", "detail": f"SSN {SSN}"}) + "\n", encoding="utf-8")
    result = audit_compliance_check(path, [SSN])
    assert not result["compliant"]
    assert result["raw_value_hits"] and result["free_text_hits"]
    assert SSN not in json.dumps(result)


def test_filename_hashing(tmp_path, entities):
    log = AuditLogger(log_path=tmp_path / "a.log", salt="s", hash_filenames=True)
    log.log_entity("d", "Payroll_John_Smith.xlsx", entities[0])
    name = _lines(log)[0]["filename"]
    assert name.startswith("sha256:") and "John" not in name


def test_hash_chain_detects_tampering(log, entities):
    for entity in entities:
        log.log_entity("d", "f.pdf", entity)
    assert log.verify_chain() == (True, None)

    lines = log.log_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["action"] = "ALLOWED"
    lines[1] = json.dumps(tampered, sort_keys=True)
    log.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert log.verify_chain() == (False, 2)


def test_chain_continues_across_logger_instances(tmp_path, entities):
    path = tmp_path / "audit.log"
    AuditLogger(log_path=path, salt="s").log_entity("d", "f.pdf", entities[0])
    AuditLogger(log_path=path, salt="s").log_entity("d", "f.pdf", entities[1])
    assert AuditLogger(log_path=path, salt="s").verify_chain() == (True, None)


def test_works_with_entity_annotation(log):
    ann = EntityAnnotation.create("PAN", "ABCPE1234F", source="ocr", page=5,
                                  bbox=[0.1, 0.2, 0.3, 0.4], confidence=0.9, action="REDACT")
    log.log_entity("d", "f.pdf", ann)
    record = _lines(log)[0]
    assert record["type"] == "PAN" and record["value_hash"] == ann.value_hash
    assert "ABCPE1234F" not in log.log_path.read_text(encoding="utf-8")


def test_read_records_filters(log, entities):
    log.log_entity("doc-a", "a.pdf", entities[0])
    log.log_entity("doc-b", "b.pdf", entities[1])
    log.log_security_event("doc-b", "b.pdf", "MAGIC_BYTE_MISMATCH")
    assert len(log.read_records(document_id="doc-b")) == 2
    assert log.read_records(event="SECURITY_EVENT")[0]["code"] == "MAGIC_BYTE_MISMATCH"
    assert len(log.read_records(limit=1)) == 1


def test_unwritable_log_raises(tmp_path, entities):
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x", encoding="utf-8")
    log = AuditLogger(log_path=blocker / "audit.log", salt="s")
    with pytest.raises(AuditLogError):
        log.log_entity("d", "f.pdf", entities[0])


def test_from_policy_uses_configured_path(tmp_path, monkeypatch):
    monkeypatch.setenv("PII_FIREWALL_AUDIT_SALT", "env-salt")
    log = AuditLogger.from_policy(log_path=tmp_path / "x.log")
    assert log.log_path == tmp_path / "x.log"
    assert log.salted_hash("v") == AuditLogger(log_path=tmp_path / "y.log", salt="env-salt").salted_hash("v")
