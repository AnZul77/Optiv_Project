"""
Independent Secondary Verifier
==============================

Re-scans SANITIZED text and reports anything that still looks like PII.
This is the security boundary: AI_READY is impossible while it reports a finding.

Independence rule
-----------------
This module does NOT import src.detection (Person 3's primary stack). A
detector's blind spot must never be verified by its own logic, so the
verifier uses a different, deliberately looser stack:

    1. Normalization  - NFKC, strip invisible format chars (zero-width, BiDi,
                        soft hyphen), strip combining marks, fold Cyrillic /
                        Greek homoglyphs to Latin, unify dash variants.
    2. De-spacing     - "S S N : 1 2 3 - 4 5 - 6 7 8 9" -> "SSN:123-45-6789"
                        (scanned as a second "compact" view of the text).
    3. Loose patterns - alternate regex dictionary (separator-tolerant SSN,
                        Luhn-checked cards, obfuscated "(at)" emails, ...).
    4. Cue scanner    - a sensitive label ("SSN:", "Passport No", "DOB")
                        followed by an un-redacted value.
    5. Digit entropy  - long digit runs with high Shannon entropy (unknown
                        IDs, masked/unformatted SSNs and card numbers).
    6. Spacing detector - letter-spaced names ("R a h u l").

Business codes from the policy allow-list (INC-2026-0417, RSK-001, ...) are
masked before scanning so they never cause a block.

Findings carry offsets and a salted value_hash, never the raw text.

**Ownership:** Person 4 (Security Policy, Independent Verification & Audit)
"""

from __future__ import annotations

import math
import re
import time
import unicodedata
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from src.policy.risk import max_risk, risk_rank
from src.schema.entities import compute_value_hash

VERIFIER_VERSION = "independent-verifier/1.0"

# =============================================================================
# Normalization
# =============================================================================

_DASHES = {c: "-" for c in "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe58\ufe63\uff0d"}

# Visually confusable Cyrillic / Greek letters -> Latin.
_HOMOGLYPHS = {
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0423": "Y", "\u0425": "X", "\u0405": "S", "\u0406": "I", "\u0408": "J",
    "\u04ae": "Y", "\u0417": "3",
    # Cyrillic lowercase
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0455": "s", "\u0456": "i", "\u0458": "j",
    "\u0501": "d", "\u04bb": "h", "\u04cf": "l", "\u043a": "k", "\u043c": "m",
    "\u043d": "h", "\u0442": "t", "\u0432": "b",
    # Greek
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O",
    "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
    "\u03bf": "o", "\u03bd": "v", "\u03b9": "i", "\u03ba": "k", "\u03c1": "p",
    "\u03b1": "a",
}


def _fold_char(ch: str) -> str:
    category = unicodedata.category(ch)
    if category in ("Cf", "Mn"):  # invisible format chars, combining marks
        return ""
    out = []
    for c in unicodedata.normalize("NFKC", ch):
        if unicodedata.category(c) in ("Cf", "Mn"):
            continue
        out.append(_HOMOGLYPHS.get(c, _DASHES.get(c, c)))
    return "".join(out)


@dataclass
class _View:
    """A transformed copy of a text plus a map back to original offsets."""

    text: str
    index_map: List[int]

    def to_original(self, start: int, end: int) -> Tuple[int, int]:
        return self.index_map[start], self.index_map[end - 1] + 1


def _normalized_view(text: str) -> _View:
    chars: List[str] = []
    index_map: List[int] = []
    for i, ch in enumerate(text):
        for folded in _fold_char(ch):
            chars.append(folded)
            index_map.append(i)
    return _View("".join(chars), index_map)


def _mask_spans(view: _View, spans: Iterable[Tuple[int, int]]) -> _View:
    chars = list(view.text)
    for start, end in spans:
        for i in range(start, end):
            chars[i] = "#"
    return _View("".join(chars), view.index_map)


def _spaced_runs(text: str, min_run: int) -> List[Tuple[int, int]]:
    pattern = re.compile(r"(?<!\S)(?:\S[ \t]{1,2}){%d,}\S(?!\S)" % max(1, min_run - 1))
    return [m.span() for m in pattern.finditer(text)]


def _compact_view(view: _View, runs: List[Tuple[int, int]]) -> _View:
    """Remove the whitespace inside letter/digit-spaced runs."""
    if not runs:
        return view
    drop = set()
    for start, end in runs:
        drop.update(i for i in range(start, end) if view.text[i] in " \t")
    chars = [c for i, c in enumerate(view.text) if i not in drop]
    index_map = [m for i, m in enumerate(view.index_map) if i not in drop]
    return _View("".join(chars), index_map)


# =============================================================================
# Validators
# =============================================================================

def _digits(value: str) -> str:
    return "".join(c for c in value if c.isdigit())


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in _digits(number)]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(number: str) -> bool:
    digits = _digits(number)
    if not digits:
        return False
    check = 0
    for i, d in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[i % 8][int(d)]]
    return check == 0


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_PHONE_CUE = re.compile(
    r"(?i)\b(?:phone|tel|telephone|mobile|cell|contact|call|direct\s+line|ph|whatsapp|fax)\b"
)
_YEAR_RANGE = re.compile(r"^(?:19|20)\d{2}\s*-\s*(?:19|20)\d{2}$")


def _id_value_ok(value: str, min_digits: int = 2) -> bool:
    first_token = value.split(" ", 1)[0]
    alnum = sum(c.isalnum() for c in value)
    return (
        alnum >= 4
        and sum(c.isdigit() for c in value) >= min_digits
        and any(c.isdigit() for c in first_token)
    )


# =============================================================================
# Findings & report
# =============================================================================

@dataclass
class ResidualFinding:
    """Something that still looks like PII after sanitization. No raw value."""

    entity_type: str
    risk: str
    detector: str
    page: int
    unit_id: str
    source: str
    start: int
    end: int
    value_hash: str
    confidence: float
    finding_id: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")

    # TextRedactor-compatible view (used by the LLM output scanner).
    @property
    def entity_id(self) -> str:
        return self.finding_id

    @property
    def text_start(self) -> int:
        return self.start

    @property
    def text_end(self) -> int:
        return self.end

    @property
    def action(self) -> str:
        return "REDACT"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "type": self.entity_type,
            "risk": self.risk,
            "detector": self.detector,
            "page": self.page,
            "unit_id": self.unit_id,
            "source": self.source,
            "span": [self.start, self.end],
            "value_hash": self.value_hash,
            "confidence": round(self.confidence, 3),
        }


@dataclass
class VerificationReport:
    findings: List[ResidualFinding] = field(default_factory=list)
    uncertain: bool = False
    errors: List[str] = field(default_factory=list)
    units_scanned: int = 0
    chars_scanned: int = 0
    duration_ms: float = 0.0
    verifier_version: str = VERIFIER_VERSION

    @property
    def passed(self) -> bool:
        return not self.findings and not self.uncertain and not self.errors

    @property
    def residual_risk(self) -> str:
        risks = [f.risk for f in self.findings]
        if self.uncertain or self.errors:
            risks.append("CRITICAL")
        return max_risk(risks)

    @property
    def status_code(self) -> str:
        if self.findings:
            return "RESIDUAL_LEAK_DETECTED"
        if self.uncertain or self.errors:
            return "VERIFIER_UNCERTAIN"
        return "VERIFIED_CLEAN"

    def merge(self, other: "VerificationReport") -> "VerificationReport":
        return VerificationReport(
            findings=self.findings + other.findings,
            uncertain=self.uncertain or other.uncertain,
            errors=self.errors + other.errors,
            units_scanned=self.units_scanned + other.units_scanned,
            chars_scanned=self.chars_scanned + other.chars_scanned,
            duration_ms=round(self.duration_ms + other.duration_ms, 2),
            verifier_version=self.verifier_version,
        )

    def counts_by_type(self) -> Dict[str, int]:
        return dict(Counter(f.entity_type for f in self.findings))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "status": self.status_code,
            "uncertain": self.uncertain,
            "residual_risk": self.residual_risk,
            "findings": [f.to_dict() for f in self.findings],
            "counts_by_type": self.counts_by_type(),
            "errors": list(self.errors),
            "units_scanned": self.units_scanned,
            "chars_scanned": self.chars_scanned,
            "duration_ms": self.duration_ms,
            "verifier_version": self.verifier_version,
        }


@dataclass
class VerificationUnit:
    """One piece of sanitized text to verify."""

    text: str
    page: int = 0
    unit_id: str = "text"
    source: str = "text"


# =============================================================================
# Rule catalog (independent of src/detection/regex.py)
# =============================================================================

@dataclass
class _Rule:
    name: str
    entity_type: str
    risk: str
    regex: re.Pattern
    confidence: float
    group: str | int = 0
    check: Optional[Callable[[re.Match, str], bool]] = None


_SEP = r"[ \-./_]"
_ID_VALUE = r"(?P<value>[A-Za-z0-9][A-Za-z0-9\-./]*(?:[ ][0-9][0-9\-./]*){0,3})"
_CUE_JOIN = r"\W{0,3}(?i:(?:number|no|num|id|#)\W{0,3})?"
_DATE_VALUE = (
    r"(?P<value>\d{1,2}[/\-. ]\d{1,2}[/\-. ]\d{2,4}"
    r"|\d{4}[/\-.]\d{1,2}[/\-.]\d{1,2}"
    r"|\d{1,2}(?:st|nd|rd|th)?[ ]+[A-Za-z]{3,9}\.?,?[ ]+\d{4}"
    r"|[A-Za-z]{3,9}\.?[ ]+\d{1,2}(?:st|nd|rd|th)?,?[ ]+\d{4})"
)


def _cue(cue: str, value: str = _ID_VALUE) -> re.Pattern:
    return re.compile(r"(?i:\b(?:" + cue + r")\b)" + _CUE_JOIN + value)


def _phone_ok(match: re.Match, text: str) -> bool:
    raw = match.group(0)
    if _YEAR_RANGE.match(raw.strip()):
        return False
    n = len(_digits(raw))
    if 10 <= n <= 15:
        return True
    if 7 <= n <= 9:
        window = text[max(0, match.start() - 25):match.start()]
        return bool(_PHONE_CUE.search(window))
    return False


def _build_rules(cue_window: int) -> List[_Rule]:
    def cue_value_ok(m: re.Match, _: str) -> bool:
        return _id_value_ok(m.group("value"))

    def phone_value_ok(m: re.Match, _: str) -> bool:
        return 7 <= len(_digits(m.group("value"))) <= 15

    filler = r"[^\n\[\u2588]{0,%d}?" % cue_window

    return [
        # ---- CRITICAL: national IDs & cards ---------------------------------
        _Rule("loose_ssn", "SSN", "CRITICAL",
              re.compile(r"(?<!\d)\d{3}" + _SEP + r"\d{2}" + _SEP + r"\d{4}(?!\d)"), 0.90),
        _Rule("luhn_card", "CARD", "CRITICAL",
              re.compile(r"(?<!\d)\d(?:[ \-]?\d){12,18}(?!\d)"), 0.95,
              check=lambda m, _: luhn_valid(m.group(0))),
        _Rule("loose_aadhaar", "AADHAAR", "CRITICAL",
              re.compile(r"(?<!\d)[2-9]\d{3}[ \-]?\d{4}[ \-]?\d{4}(?!\d)"), 0.85,
              check=lambda m, _: verhoeff_valid(m.group(0))),
        _Rule("loose_pan", "PAN", "CRITICAL",
              re.compile(r"(?i)\b[A-Z]{5}\d{4}[A-Z]\b"), 0.85),
        _Rule("loose_nino", "NINO", "CRITICAL",
              re.compile(r"(?i)\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]"
                         r" ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b"), 0.80),
        _Rule("cue_passport", "PASSPORT", "CRITICAL",
              re.compile(r"(?i:\bpassport\b)" + filler +
                         r"\b(?P<value>[A-Z]{1,2}[ \-]?\d{6,9}|\d{9})\b"), 0.85, group="value"),
        _Rule("cue_ssn", "SSN", "CRITICAL", _cue(r"ssn|social\s+security"), 0.85,
              group="value", check=cue_value_ok),
        _Rule("cue_tax_id", "TAX_ID", "CRITICAL",
              _cue(r"tax\s*id|taxpayer\s+id|tin|ein|itin"), 0.80, group="value", check=cue_value_ok),
        _Rule("cue_pan", "PAN", "CRITICAL", _cue(r"pan(?:\s+card)?"), 0.80,
              group="value", check=cue_value_ok),
        _Rule("cue_aadhaar", "AADHAAR", "CRITICAL", _cue(r"aadhaar|aadhar|uidai|uid"), 0.85,
              group="value", check=cue_value_ok),
        _Rule("cue_nino", "NINO", "CRITICAL", _cue(r"nino|national\s+insurance"), 0.80,
              group="value", check=cue_value_ok),
        _Rule("cue_card", "CARD", "CRITICAL",
              _cue(r"(?:credit\s+|debit\s+)?card"), 0.75, group="value",
              check=lambda m, _: len(_digits(m.group("value"))) >= 8),

        # ---- HIGH: contact, identity, org IDs --------------------------------
        _Rule("loose_email", "EMAIL", "HIGH",
              re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}"
                         r"(?:\.[A-Za-z0-9\-]{1,63}){0,8}\.[A-Za-z]{2,24}"), 0.95),
        _Rule("obfuscated_email", "EMAIL", "HIGH",
              re.compile(r"(?i)[A-Za-z0-9._%+\-]{1,64}[ \t]{0,3}[\[\(\{][ \t]{0,3}at[ \t]{0,3}[\]\)\}]"
                         r"[ \t]{0,3}[A-Za-z0-9\-]{1,63}(?:[ \t]{0,3}(?:[\[\(\{][ \t]{0,3}dot[ \t]{0,3}"
                         r"[\]\)\}]|\.)[ \t]{0,3}[A-Za-z0-9\-]{1,63}){1,8}"), 0.85),
        _Rule("loose_phone", "PHONE", "HIGH",
              re.compile(r"(?<![\w#])(?:\+\d{1,3}[ \-.]?)?(?:\(\d{1,4}\)[ \-.]?)?"
                         r"\d{2,4}(?:[ \-.]\d{2,4}){1,3}(?![\w#])"), 0.75, check=_phone_ok),
        _Rule("cue_phone", "PHONE", "HIGH",
              re.compile(r"(?i:\b(?:phone|mobile|tel|telephone|cell|direct\s+line"
                         r"|contact\s+(?:number|no))\b)\W{0,4}"
                         r"(?P<value>\+?[0-9][0-9 \-().]{5,20}[0-9])"), 0.80,
              group="value", check=phone_value_ok),
        _Rule("cue_dob", "DOB", "HIGH",
              re.compile(r"(?i:\b(?:dob|d\.o\.b|date\s+of\s+birth|birth\s*date|born(?:\s+on)?)\b)"
                         + filler + _DATE_VALUE), 0.85, group="value"),
        _Rule("loose_employee_id", "EMPLOYEE_ID", "HIGH",
              re.compile(r"(?i)\bEMP[-_ ]?\d{3,}\b"), 0.85),
        _Rule("cue_employee_id", "EMPLOYEE_ID", "HIGH",
              _cue(r"employee\s+(?:id|no|number)|emp\s+(?:id|no)|staff\s+id"), 0.80,
              group="value", check=cue_value_ok),
        _Rule("cue_director_id", "DIRECTOR_ID", "HIGH",
              _cue(r"director\s+id|din"), 0.80, group="value", check=cue_value_ok),
        _Rule("cue_bank_account", "BANK_ACCOUNT", "HIGH",
              _cue(r"account|a/c|acct|iban"), 0.80, group="value",
              check=lambda m, _: len(_digits(m.group("value"))) >= 6),
        _Rule("honorific_name", "PERSON", "HIGH",
              re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Shri|Smt|Sri)\.?[ ]+"
                         r"[A-Z][a-z]+(?:[ ]+[A-Z][a-z]+)?"), 0.70),
        _Rule("cue_name", "PERSON", "HIGH",
              re.compile(r"(?i:\b(?:full\s+name|employee\s+name|customer\s+name|patient\s+name"
                         r"|holder\s+name|contact\s+name|(?<!file )(?<!user )(?<!host )"
                         r"(?<!domain )(?<!policy )name))\s*[:\-]\s*"
                         r"(?P<value>[A-Z][a-z]+(?:[ ]+[A-Z][a-zA-Z'\-]+){1,3})"), 0.75,
              group="value"),
        _Rule("street_address", "ADDRESS", "HIGH",
              re.compile(r"\b\d{1,5}[ ]{1,3}(?:[A-Z][a-z]{1,30}[ ]{1,3}){1,4}(?:Street|St|Road|Rd|Avenue|Ave"
                         r"|Lane|Ln|Boulevard|Blvd|Drive|Court|Ct|Nagar|Marg)\b\.?"), 0.70),

        # ---- MEDIUM: Indian financial codes ----------------------------------
        _Rule("loose_ifsc", "IFSC", "MEDIUM", re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), 0.80),
        _Rule("loose_gst", "GST", "MEDIUM",
              re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]\b"), 0.85),
        _Rule("loose_upi", "UPI", "MEDIUM",
              re.compile(r"\b[A-Za-z0-9.\-_]{2,64}@[A-Za-z]{2,32}\b(?!\.[A-Za-z])"), 0.70),
    ]


_DIGIT_RUNS = (
    re.compile(r"(?<![\w#])\d+(?:-\d+)*(?![\w#])"),
    re.compile(r"(?<![\w#])\d{4}(?: \d{4}){2,4}(?![\w#])"),
)
_CAPITALIZED_WORD = re.compile(r"[A-Z][a-z]{2,}")

# Catch-all labels that yield to a specific type when spans overlap.
_GENERIC_TYPES = frozenset({"NUMERIC_ID"})


# =============================================================================
# Verifier
# =============================================================================

class IndependentVerifier:
    """Heterogeneous secondary PII scanner for sanitized output."""

    def __init__(
        self,
        allow_list_patterns: Optional[Sequence[str]] = None,
        settings: Optional[Dict[str, Any]] = None,
    ):
        settings = settings or {}
        self.digit_run_min = int(settings.get("digit_run_min_length", 9))
        self.digit_run_max = int(settings.get("digit_run_max_length", 19))
        self.entropy_threshold = float(settings.get("digit_entropy_threshold", 2.5))
        self.spacing_min_run = int(settings.get("spacing_min_run", 4))
        self.cue_window = int(settings.get("cue_window_chars", 30))
        self._allow_list = [re.compile(p) for p in (allow_list_patterns or [])]
        self._rules = _build_rules(self.cue_window)

    @classmethod
    def from_policy(cls, policy: Any = None) -> "IndependentVerifier":
        """Build from a PolicyEngine / PolicyConfig; None loads config/policy.yaml."""
        if policy is None:
            from src.policy.policy import PolicyConfig
            policy = PolicyConfig.load()
        config = getattr(policy, "config", policy)
        return cls(allow_list_patterns=config.allow_list_patterns, settings=config.verification)

    # ------------------------------------------------------------------ scanning
    def scan_text(
        self, text: str, page: int = 0, unit_id: str = "text", source: str = "text"
    ) -> List[ResidualFinding]:
        """Return de-duplicated findings for one text. Raises on internal errors."""
        if not text or not text.strip():
            return []

        normalized = _normalized_view(text)
        allow_spans = [m.span() for p in self._allow_list for m in p.finditer(normalized.text)]
        normalized = _mask_spans(normalized, allow_spans)
        runs = _spaced_runs(normalized.text, self.spacing_min_run)
        compact = _compact_view(normalized, runs)

        raw: List[Tuple[int, int, str, str, str, float]] = []

        def add(view: _View, start: int, end: int, entity_type: str, risk: str,
                detector: str, confidence: float) -> None:
            if end <= start:
                return
            o_start, o_end = view.to_original(start, end)
            raw.append((o_start, o_end, entity_type, risk, detector, confidence))

        views = (normalized,) if compact is normalized else (normalized, compact)
        for view in views:
            for rule in self._rules:
                for match in rule.regex.finditer(view.text):
                    if rule.check and not rule.check(match, view.text):
                        continue
                    start, end = match.span(rule.group)
                    add(view, start, end, rule.entity_type, rule.risk, rule.name, rule.confidence)

            for pattern in _DIGIT_RUNS:
                for match in pattern.finditer(view.text):
                    digits = _digits(match.group(0))
                    if len(digits) < self.digit_run_min:
                        continue
                    if len(digits) <= self.digit_run_max and \
                            shannon_entropy(digits) < self.entropy_threshold:
                        continue
                    add(view, *match.span(), "NUMERIC_ID", "CRITICAL", "digit_entropy", 0.70)

        for start, end in runs:
            collapsed = re.sub(r"[ \t]", "", normalized.text[start:end])
            if sum(c.isalpha() for c in collapsed) >= self.spacing_min_run \
                    and _CAPITALIZED_WORD.search(collapsed):
                add(normalized, start, end, "PERSON", "HIGH", "spacing_evasion", 0.65)

        return self._merge(raw, text, page, unit_id, source)

    @staticmethod
    def _merge(raw, text, page, unit_id, source) -> List[ResidualFinding]:
        """Merge overlapping hits: widest span, worst risk, most specific type label."""
        merged: List[List[Any]] = []
        for start, end, etype, risk, detector, conf in sorted(raw, key=lambda r: (r[0], -r[1])):
            if merged and start < merged[-1][1]:
                cur = merged[-1]
                cur[1] = max(cur[1], end)
                cur_generic, new_generic = cur[2] in _GENERIC_TYPES, etype in _GENERIC_TYPES
                if (cur_generic and not new_generic) or (
                    cur_generic == new_generic and risk_rank(risk) > risk_rank(cur[3])
                ):
                    cur[2] = etype
                if risk_rank(risk) > risk_rank(cur[3]):
                    cur[3] = risk
                if detector not in cur[4]:
                    cur[4].append(detector)
                cur[5] = max(cur[5], conf)
            else:
                merged.append([start, end, etype, risk, [detector], conf])

        return [
            ResidualFinding(
                entity_type=etype,
                risk=risk,
                detector="+".join(detectors),
                page=page,
                unit_id=unit_id,
                source=source,
                start=start,
                end=end,
                value_hash=compute_value_hash(text[start:end]),
                confidence=conf,
            )
            for start, end, etype, risk, detectors, conf in merged
        ]

    # ------------------------------------------------------------------ reports
    def verify_units(self, units: Iterable[VerificationUnit]) -> VerificationReport:
        """Scan every unit. Never raises: internal errors make the report uncertain."""
        started = time.perf_counter()
        report = VerificationReport()
        try:
            for unit in units:
                report.units_scanned += 1
                report.chars_scanned += len(unit.text or "")
                try:
                    report.findings.extend(
                        self.scan_text(unit.text, unit.page, unit.unit_id, unit.source)
                    )
                except Exception as exc:  # fail closed on any scanner fault
                    report.uncertain = True
                    report.errors.append(f"{unit.unit_id}: verifier error {type(exc).__name__}")
        except Exception as exc:
            report.uncertain = True
            report.errors.append(f"verifier input error {type(exc).__name__}")

        if report.units_scanned == 0:
            report.uncertain = True
            report.errors.append("nothing to verify: no text units supplied")

        report.duration_ms = round((time.perf_counter() - started) * 1000, 2)
        return report

    def verify_text(
        self, text: str, page: int = 0, unit_id: str = "text", source: str = "text"
    ) -> VerificationReport:
        return self.verify_units([VerificationUnit(text or "", page, unit_id, source)])

    def verify_blocks(self, blocks: Iterable[Any], source: str = "block") -> VerificationReport:
        """Blocks are duck-typed: `.text`, `.page`, `.block_id` (ContentBlock / ExtractedBlock)."""
        units = [
            VerificationUnit(
                text=getattr(b, "text", "") or "",
                page=int(getattr(b, "page", 0) or 0),
                unit_id=str(getattr(b, "block_id", "") or f"block_{i}"),
                source=source,
            )
            for i, b in enumerate(blocks)
        ]
        return self.verify_units(units)

    def verify_document(self, document: Any) -> VerificationReport:
        """Scan every text channel of a (sanitized) CanonicalDocument."""
        return self.verify_units(document_units(document))


def _walk_strings(value: Any, path: str, depth: int = 0) -> Iterable[Tuple[str, str]]:
    if depth > 3:
        return
    if isinstance(value, str):
        if value.strip():
            yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _walk_strings(item, f"{path}.{key}", depth + 1)
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            yield from _walk_strings(item, f"{path}[{i}]", depth + 1)


def document_units(document: Any) -> List[VerificationUnit]:
    """Every text channel of a CanonicalDocument: blocks, OCR, tables, image OCR, metadata."""
    units: List[VerificationUnit] = []
    pages = getattr(document, "pages_dict", {}) or {}
    for page_num in sorted(pages):
        page = pages[page_num]
        blocks = getattr(page, "blocks", []) or []
        for block in blocks:
            units.append(VerificationUnit(block.text or "", page_num, block.block_id, "block"))
        if not blocks and getattr(page, "native_text", ""):
            units.append(VerificationUnit(page.native_text, page_num, f"page_{page_num}_native", "native"))
        ocr_text = getattr(page, "ocr_text", "") or ""
        if ocr_text and ocr_text != getattr(page, "native_text", ""):
            units.append(VerificationUnit(ocr_text, page_num, f"page_{page_num}_ocr", "ocr"))
        for table in getattr(page, "tables", []) or []:
            for row in table.rows:
                for cell in row:
                    units.append(VerificationUnit(
                        cell.text or "", page_num,
                        f"table_{table.table_index}_r{cell.row_idx}_c{cell.col_idx}", "table_cell",
                    ))
        for image in getattr(page, "images", []) or []:
            if getattr(image, "ocr_text", ""):
                units.append(VerificationUnit(image.ocr_text, page_num, image.image_id, "image_ocr"))

    for path, text in _walk_strings(getattr(document, "metadata", {}) or {}, "metadata"):
        units.append(VerificationUnit(text, 0, path, "metadata"))
    return units


def verify_document(target: Any, policy: Any = None) -> VerificationReport:
    """
    Convenience entry point.

    `target` may be a string, a CanonicalDocument, or a list of blocks.
    """
    verifier = IndependentVerifier.from_policy(policy)
    if isinstance(target, str):
        return verifier.verify_text(target)
    if hasattr(target, "pages_dict"):
        return verifier.verify_document(target)
    return verifier.verify_blocks(target)
