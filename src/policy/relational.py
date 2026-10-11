"""
Relational Privacy Engine
==========================

Implements Contextual Integrity & Relational Privacy (Nissenbaum Model)
using Syntactic Dependency Parsing (Subject-Verb-Object action triples)
and Sensitive Attribute Coupling.

Differentiates between:
1. Public / Literary / Historical statements:
   "J.K. Rowling wrote Harry Potter" -> ALLOW (Preserves knowledge utility)
2. Private / Financial / Health / HR transactions:
   "Anshul transferred $10k to Optiv" -> REDACT (Prevents privacy leak)
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Action Predicates & Sensitivity Catalogs
# =============================================================================

# Verbs representing sensitive personal, financial, HR, or health actions
SENSITIVE_PREDICATES: Set[str] = {
    # Financial transactions & compensation
    "transfer", "wire", "pay", "deposit", "earn", "owe", "spend", "remit",
    "invoice", "bill", "refund", "withdraw", "invest", "borrow", "loan",
    "transact", "purchase", "charge", "compensate", "reimburse",
    # HR, disciplinary, background, and performance
    "terminate", "discipline", "fire", "suspend", "reprimand", "investigate",
    "accuse", "sanction", "demote", "penalize", "audit", "violate",
    # Health, medical, and psychological
    "diagnose", "prescribe", "treat", "admit", "suffer", "contract", "infect",
    # Private / domestic / legal status
    "reside", "live", "marry", "divorce", "arrest", "convict", "sue",
}

# Verbs representing public authorship, scientific discovery, creative creation, or public leadership
PUBLIC_PREDICATES: Set[str] = {
    # Creative, literary, artistic
    "write", "author", "publish", "compose", "direct", "paint", "sculpt",
    "create", "produce", "illustrate", "narrate",
    # Intellectual, scientific, academic
    "invent", "discover", "formulate", "theorize", "pioneer", "prove",
    "establish", "hypothesize", "calculate", "postulate",
    # Public history & leadership
    "found", "pioneer", "coin", "originate", "establish",
}

# Regex to detect sensitive anchors (money amounts, account/ID cues) in a clause
FINANCIAL_ANCHOR_REGEX = re.compile(
    r"(?:\$|€|£|₹|USD|EUR|GBP|INR)\s*\d+(?:[.,]\d+)*(?:\s*(?:k|m|b|thousand|million|crore|lakh))?|\b\d+(?:[.,]\d+)*\s*(?:k|usd|eur|inr|dollars|rupees|pounds)\b|\b(?:\d+k)\b",
    re.IGNORECASE,
)

HEALTH_ANCHOR_REGEX = re.compile(
    r"\b(?:diagnosed|prescription|medication|hospitalized|patient|disease|illness|treatment|clinic|therapy)\b",
    re.IGNORECASE,
)

HR_ANCHOR_REGEX = re.compile(
    r"\b(?:performance review|disciplinary action|termination|reprimand|probation|salary of|annual bonus|pip)\b",
    re.IGNORECASE,
)


@dataclass
class RelationalAssessment:
    """Assessment of whether an entity in its syntactic context is sensitive PII."""

    is_sensitive: bool
    linkability_score: float
    predicate: Optional[str]
    subject: Optional[str]
    object_target: Optional[str]
    sensitive_anchors: List[str] = field(default_factory=list)
    reason: str = ""


class RelationalPrivacyEngine:
    """
    Evaluates context-dependent sensitivity of named entities in text.

    Uses spaCy dependency parsing to inspect grammatical predicates and
    neighboring sensitive attribute anchors.
    """

    def __init__(self, nlp=None):
        self._nlp = nlp

    def _ensure_nlp(self):
        if self._nlp is None:
            import spacy
            try:
                self._nlp = spacy.load("en_core_web_sm")
            except OSError:
                logger.warning("en_core_web_sm not installed, using blank English model.")
                self._nlp = spacy.blank("en")
        return self._nlp

    def assess_entity_in_sentence(
        self,
        sentence_text: str,
        entity_value: str,
        entity_type: str = "PERSON",
    ) -> RelationalAssessment:
        """
        Evaluate if entity_value in sentence_text constitutes sensitive personal PII.

        Returns RelationalAssessment with is_sensitive (bool) and linkability_score (0.0 to 1.0).
        """
        if not sentence_text or not entity_value:
            return RelationalAssessment(is_sensitive=True, linkability_score=0.8, predicate=None, subject=None, object_target=None, reason="Empty input")

        # 1. Non-PERSON entities (SSN, Passport, Card, Phone, Email) are inherently sensitive
        if entity_type not in ("PERSON", "NAME"):
            return RelationalAssessment(
                is_sensitive=True,
                linkability_score=0.95,
                predicate=None,
                subject=entity_value,
                object_target=None,
                reason=f"Inherently sensitive entity type: {entity_type}",
            )

        nlp = self._ensure_nlp()
        doc = nlp(sentence_text)

        # 2. Check for Sensitive Attribute Anchors in the sentence
        sensitive_anchors = []
        if FINANCIAL_ANCHOR_REGEX.search(sentence_text):
            sensitive_anchors.append("financial_amount")
        if HEALTH_ANCHOR_REGEX.search(sentence_text):
            sensitive_anchors.append("health_indicator")
        if HR_ANCHOR_REGEX.search(sentence_text):
            sensitive_anchors.append("hr_indicator")

        # 3. Locate the entity token(s) and extract Action Triples
        predicate_lemma = None
        subject_text = None
        object_text = None

        entity_clean = entity_value.strip().lower()

        for token in doc:
            if token.text.lower() in entity_clean or entity_clean in token.text.lower():
                # Climb ancestor chain to find the governing verb
                curr = token
                while curr and curr.head != curr:
                    if curr.head.pos_ == "VERB":
                        predicate_lemma = curr.head.lemma_.lower()
                        # Extract subject and object from governing verb
                        for child in curr.head.children:
                            if child.dep_ in ("nsubj", "nsubjpass"):
                                subject_text = child.text
                            elif child.dep_ in ("dobj", "pobj", "attr"):
                                object_text = child.text
                        break
                    curr = curr.head

                if predicate_lemma:
                    break

        # 4. Relational Scoring Decision
        # Scenario A: Presence of sensitive financial/health/HR anchors
        if sensitive_anchors:
            return RelationalAssessment(
                is_sensitive=True,
                linkability_score=0.95,
                predicate=predicate_lemma,
                subject=subject_text or entity_value,
                object_target=object_text,
                sensitive_anchors=sensitive_anchors,
                reason=f"Coupled with sensitive anchors: {', '.join(sensitive_anchors)}",
            )

        # Scenario B: Verb is explicitly sensitive (transferred, earned, fired, diagnosed)
        if predicate_lemma in SENSITIVE_PREDICATES:
            return RelationalAssessment(
                is_sensitive=True,
                linkability_score=0.90,
                predicate=predicate_lemma,
                subject=subject_text or entity_value,
                object_target=object_text,
                reason=f"Sensitive action predicate: '{predicate_lemma}'",
            )

        # Scenario C: Verb is public / literary / historical (wrote, published, discovered)
        if predicate_lemma in PUBLIC_PREDICATES:
            return RelationalAssessment(
                is_sensitive=False,
                linkability_score=0.10,
                predicate=predicate_lemma,
                subject=subject_text or entity_value,
                object_target=object_text,
                reason=f"Public informational predicate: '{predicate_lemma}' (Zero privacy harm)",
            )

        # Scenario D: Corporate / Organization description (Optiv is the leader...)
        if any(word in sentence_text.lower() for word in ["leader", "solutions", "advisory", "delivering", "founded in"]):
            if entity_value.lower() in sentence_text.lower():
                return RelationalAssessment(
                    is_sensitive=False,
                    linkability_score=0.15,
                    predicate=predicate_lemma,
                    subject=entity_value,
                    object_target=object_text,
                    reason="Corporate advisory / descriptive statement",
                )

        # Default fallback for PERSON without specific sensitive anchors
        # In enterprise documents with no explicit sensitive anchors, default to moderate linkability
        return RelationalAssessment(
            is_sensitive=True,
            linkability_score=0.75,
            predicate=predicate_lemma,
            subject=subject_text or entity_value,
            object_target=object_text,
            reason="Enterprise personal identifier",
        )
