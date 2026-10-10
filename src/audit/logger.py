"""
Zero-PII Audit Logger
=====================

Append-only JSONL audit trail (default: data/outputs/audit.log, git-ignored).

One line per event:
    ENTITY_DECISION   - every detected entity: type, salted value_hash, page,
                        bbox, action (REDACTED / BLOCKED / ALLOWED) + gate decision
    VERIFIER_FINDING  - every residual finding from the independent verifier
    GATE_DECISION     - one summary line per document (PASS / BLOCK + reasons)
    SECURITY_EVENT    - ingestion rejections etc. (SIZE_LIMIT_EXCEEDED, ...)

Zero-PII guarantees:
    * Records are built from a fixed whitelist of fields; raw entity values
      (PIIEntity.value) are never read.
    * Free-text fields (filename, reason details) are re-scanned with the
      independent verifier; anything that looks like PII is replaced by
      "[SCRUBBED:<salted hash prefix>]".
    * Only the file's basename is kept (directory paths can contain user names);
      with audit.hash_filenames=true the name is stored as a salted hash.
    * Optional hash chain (prev_hash / record_hash) makes edits or deleted
      lines detectable with verify_chain().

`audit_compliance_check()` is the Day 15 check: scan a log file for any raw
sensitive value and any PII-looking free text.

**Ownership:** Person 4 (Security Policy, Independent Verification & Audit)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from src.policy.risk import (
    entity_action_name,
    entity_risk_name,
    entity_type_name,
)

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64
DEV_SALT = "pii-firewall-audit-dev-salt-change-in-production"

ACTION_PAST_TENSE = {
    "REDACT": "REDACTED",
    "BLOCK": "BLOCKED",
    "ALLOW": "ALLOWED",
    "PASS": "ALLOWED",
    "REVIEW": "FLAGGED_FOR_REVIEW",
}

FREE_TEXT_FIELDS = ("filename", "detail", "reasons", "document_id")


class AuditLogError(RuntimeError):
    """The audit trail could not be written. Callers must fail closed."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _bbox(value: Any) -> Optional[List[float]]:
    if value is None:
        return None
    try:
        coords = [round(float(v), 4) for v in value]
    except (TypeError, ValueError):
        return None
    return coords if len(coords) == 4 else None


class AuditLogger:
    """Thread-safe, append-only, zero-PII JSONL audit logger."""

    def __init__(
        self,
        log_path: Optional[str | Path] = None,
        salt: Optional[str] = None,
        hash_filenames: bool = False,
        hash_chain: bool = True,
        scrubber: Any = None,
    ):
        if log_path is None:
            from src.policy.policy import PROJECT_ROOT, SECTION_DEFAULTS
            log_path = PROJECT_ROOT / SECTION_DEFAULTS["audit"]["log_path"]
        self.log_path = Path(log_path)
        self.hash_filenames = hash_filenames
        self.hash_chain = hash_chain
        self._lock = threading.Lock()

        if not salt:
            salt = os.environ.get("PII_FIREWALL_AUDIT_SALT")
        if not salt:
            logger.warning("Audit salt not configured; using development salt.")
            salt = DEV_SALT
        self._salt = salt

        if scrubber is None:
            from src.verification.verifier import IndependentVerifier
            scrubber = IndependentVerifier()
        self._scrubber = scrubber
        self._last_hash = self._load_last_hash() if hash_chain else None

    @classmethod
    def from_policy(cls, policy: Any = None, log_path: Optional[str | Path] = None) -> "AuditLogger":
        from src.policy.policy import PolicyConfig
        from src.verification.verifier import IndependentVerifier

        config = getattr(policy, "config", policy) if policy is not None else PolicyConfig.load()
        settings = config.audit
        return cls(
            log_path=log_path or config.resolve_path(settings["log_path"]),
            salt=os.environ.get(settings.get("salt_env_var", "PII_FIREWALL_AUDIT_SALT")),
            hash_filenames=bool(settings.get("hash_filenames", False)),
            hash_chain=bool(settings.get("hash_chain", True)),
            scrubber=IndependentVerifier.from_policy(config),
        )

    # ------------------------------------------------------------------ hygiene
    def salted_hash(self, value: str) -> str:
        return hashlib.sha256(f"{self._salt}:{value}".encode("utf-8")).hexdigest()

    def _scrub(self, value: Any) -> str:
        text = "" if value is None else str(value)
        try:
            leaks = self._scrubber.scan_text(text)
        except Exception:
            leaks = [True]  # cannot confirm -> scrub
        return f"[SCRUBBED:{self.salted_hash(text)[:16]}]" if leaks else text

    def _filename(self, filename: Any) -> str:
        name = os.path.basename(str(filename or ""))
        if not name:
            return ""
        if self.hash_filenames:
            return f"sha256:{self.salted_hash(name)}"
        return self._scrub(name)

    # ------------------------------------------------------------------ writing
    def _load_last_hash(self) -> str:
        if not self.log_path.is_file():
            return GENESIS_HASH
        last = GENESIS_HASH
        try:
            with self.log_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        last = json.loads(line).get("record_hash", last)
        except (OSError, ValueError):
            logger.warning("Existing audit log unreadable; starting a new hash chain.")
            return GENESIS_HASH
        return last

    def _write(self, record: Dict[str, Any]) -> Dict[str, Any]:
        record.setdefault("timestamp", _utc_now())
        with self._lock:
            if self.hash_chain:
                record["prev_hash"] = self._last_hash
                payload = json.dumps(record, sort_keys=True, ensure_ascii=False)
                record["record_hash"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            line = json.dumps(record, sort_keys=True, ensure_ascii=False)
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.log_path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
            except OSError as exc:
                raise AuditLogError(f"cannot write audit log: {exc}") from exc
            if self.hash_chain:
                self._last_hash = record["record_hash"]
        return record

    # ------------------------------------------------------------------ events
    def log_entity(
        self,
        document_id: str,
        filename: str,
        entity: Any,
        gate_decision: str = "",
    ) -> Dict[str, Any]:
        action = entity_action_name(entity)
        return self._write({
            "event": "ENTITY_DECISION",
            "document_id": self._scrub(document_id),
            "filename": self._filename(filename),
            "entity_id": str(getattr(entity, "entity_id", "")),
            "type": entity_type_name(entity),
            "value_hash": str(getattr(entity, "value_hash", "") or ""),
            "page": int(getattr(entity, "page", 0) or 0),
            "bbox": _bbox(getattr(entity, "bbox", None)),
            "source": str(_enum_value(getattr(entity, "source", "")) or ""),
            "confidence": round(float(getattr(entity, "confidence", 0.0) or 0.0), 4),
            "risk": entity_risk_name(entity),
            "action": ACTION_PAST_TENSE.get(action, action or "UNKNOWN"),
            "gate_decision": gate_decision,
        })

    def log_verifier_findings(
        self,
        document_id: str,
        filename: str,
        verification_report: Any,
        gate_decision: str = "",
    ) -> int:
        count = 0
        for finding in getattr(verification_report, "findings", []) or []:
            self._write({
                "event": "VERIFIER_FINDING",
                "document_id": self._scrub(document_id),
                "filename": self._filename(filename),
                "finding_id": finding.finding_id,
                "type": finding.entity_type,
                "risk": finding.risk,
                "detector": finding.detector,
                "page": finding.page,
                "unit_id": self._scrub(finding.unit_id),
                "source": finding.source,
                "value_hash": finding.value_hash,
                "action": "BLOCKED",
                "gate_decision": gate_decision,
            })
            count += 1
        return count

    def log_gate_decision(
        self,
        document_id: str,
        filename: str,
        gate_decision: Any,
        policy_result: Any = None,
        verification_report: Any = None,
    ) -> Dict[str, Any]:
        reasons = [
            {"code": r.code, "detail": self._scrub(r.detail)}
            for r in getattr(gate_decision, "reasons", []) or []
        ]
        record = {
            "event": "GATE_DECISION",
            "document_id": self._scrub(document_id),
            "filename": self._filename(filename),
            "gate_decision": getattr(gate_decision, "decision", "BLOCK"),
            "ai_ready": bool(getattr(gate_decision, "ai_ready", False)),
            "status_code": getattr(gate_decision, "status_code", "BLOCKED"),
            "reasons": reasons,
            "inherent_risk": getattr(gate_decision, "inherent_risk", ""),
            "residual_risk": getattr(gate_decision, "residual_risk", ""),
            "policy_version": getattr(gate_decision, "policy_version", ""),
        }
        if policy_result is not None:
            record["action_counts"] = dict(getattr(policy_result, "action_counts", {}) or {})
        if verification_report is not None:
            record["verification"] = {
                "status": verification_report.status_code,
                "findings": len(verification_report.findings),
                "counts_by_type": verification_report.counts_by_type(),
                "units_scanned": verification_report.units_scanned,
                "verifier_version": verification_report.verifier_version,
            }
        return self._write(record)

    def log_security_event(
        self, document_id: str, filename: str, code: str, detail: str = ""
    ) -> Dict[str, Any]:
        """For pre-flight rejections (SIZE_LIMIT_EXCEEDED, MAGIC_BYTE_MISMATCH, ZIP_BOMB_DETECTED...)."""
        return self._write({
            "event": "SECURITY_EVENT",
            "document_id": self._scrub(document_id),
            "filename": self._filename(filename),
            "code": str(code),
            "detail": self._scrub(detail),
            "gate_decision": "BLOCK",
        })

    def log_document(
        self,
        document_id: str,
        filename: str,
        entities: Iterable[Any],
        gate_decision: Any,
        policy_result: Any = None,
        verification_report: Any = None,
    ) -> int:
        """Write the full trail for one document. Returns the number of records written."""
        decision = getattr(gate_decision, "decision", "BLOCK")
        written = 0
        for entity in entities:
            self.log_entity(document_id, filename, entity, decision)
            written += 1
        if verification_report is not None:
            written += self.log_verifier_findings(document_id, filename, verification_report, decision)
        self.log_gate_decision(document_id, filename, gate_decision, policy_result, verification_report)
        return written + 1

    # ------------------------------------------------------------------ reading
    def read_records(
        self,
        document_id: Optional[str] = None,
        event: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Records (newest last). Handy for the Streamlit audit table."""
        if not self.log_path.is_file():
            return []
        records = []
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if document_id and record.get("document_id") != document_id:
                    continue
                if event and record.get("event") != event:
                    continue
                records.append(record)
        return records[-limit:] if limit else records

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        """(True, None) if intact; otherwise (False, first bad line number)."""
        if not self.log_path.is_file():
            return True, None
        prev = GENESIS_HASH
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    return False, line_no
                stored = record.pop("record_hash", None)
                if record.get("prev_hash") != prev:
                    return False, line_no
                payload = json.dumps(record, sort_keys=True, ensure_ascii=False)
                if hashlib.sha256(payload.encode("utf-8")).hexdigest() != stored:
                    return False, line_no
                prev = stored
        return True, None


def audit_compliance_check(
    log_path: str | Path,
    sensitive_values: Sequence[str] = (),
    scrubber: Any = None,
) -> Dict[str, Any]:
    """
    Day 15 compliance check: confirm zero raw PII in an audit log.

    Args:
        log_path:         The JSONL audit log to inspect.
        sensitive_values: Raw values known to be in the source documents (e.g. the
                          ground-truth values); none may appear anywhere in the log.
        scrubber:         Scanner with scan_text(); defaults to the independent verifier.

    Returns:
        {"compliant": bool, "lines": int, "raw_value_hits": [...], "free_text_hits": [...]}
    """
    if scrubber is None:
        from src.verification.verifier import IndependentVerifier
        scrubber = IndependentVerifier()

    path = Path(log_path)
    raw_hits: List[Dict[str, Any]] = []
    text_hits: List[Dict[str, Any]] = []
    lines = 0
    needles = [v for v in sensitive_values if v and len(v.strip()) >= 3]

    if path.is_file():
        with path.open("r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                lines += 1
                for needle in needles:
                    if needle in line:
                        raw_hits.append({"line": line_no, "value_hash": hashlib.sha256(
                            needle.encode("utf-8")).hexdigest()[:16]})
                try:
                    record = json.loads(line)
                except ValueError:
                    text_hits.append({"line": line_no, "field": "<unparseable>"})
                    continue
                for field_name in FREE_TEXT_FIELDS:
                    value = record.get(field_name)
                    if field_name == "reasons" and isinstance(value, list):
                        value = " ".join(str(r.get("detail", "")) for r in value if isinstance(r, dict))
                    if value and scrubber.scan_text(str(value)):
                        text_hits.append({"line": line_no, "field": field_name})

    return {
        "compliant": not raw_hits and not text_hits,
        "lines": lines,
        "raw_value_hits": raw_hits,
        "free_text_hits": text_hits,
    }
