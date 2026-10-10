"""
Policy Package (Person 4)
=========================

- risk.py:   inherent vs. residual risk scoring (critical dominance)
- policy.py: config/policy.yaml loader and REDACT / BLOCK / ALLOW engine
"""

from src.policy.risk import (
    RISK_ORDER,
    RiskAssessment,
    inherent_risk,
    max_risk,
    normalize_risk,
    residual_risk,
    risk_exceeds,
)
from src.policy.policy import (
    DEFAULT_POLICY_PATH,
    PolicyConfig,
    PolicyConfigError,
    PolicyDecision,
    PolicyEngine,
    PolicyResult,
    load_policy,
)

__all__ = [
    "RISK_ORDER",
    "RiskAssessment",
    "inherent_risk",
    "max_risk",
    "normalize_risk",
    "residual_risk",
    "risk_exceeds",
    "DEFAULT_POLICY_PATH",
    "PolicyConfig",
    "PolicyConfigError",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyResult",
    "load_policy",
]
