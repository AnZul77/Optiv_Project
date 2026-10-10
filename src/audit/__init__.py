"""
Audit Package (Person 4)
========================

- logger.py: zero-PII, salted-hash, append-only JSONL audit trail
"""

from src.audit.logger import (
    ACTION_PAST_TENSE,
    AuditLogError,
    AuditLogger,
    audit_compliance_check,
)

__all__ = [
    "ACTION_PAST_TENSE",
    "AuditLogError",
    "AuditLogger",
    "audit_compliance_check",
]
