"""
Text Redaction Engine
=====================

Provides text-level PII sanitization by replacing sensitive spans
with either semantic tags (e.g. `[REDACTED:EMAIL]`) or opaque character masks (e.g. `████████`).

Supports:
- Offset-based span replacement (precise character bounds)
- Value-based dictionary replacement
- Fallback mask styles
"""

from typing import Dict, List, Optional, Sequence, Union
import re


def redact_text_by_spans(
    text: str,
    spans: Sequence[Dict[str, Union[int, str]]],
    mask_format: str = "[REDACTED:{type}]",
) -> str:
    """
    Replace text spans with redaction tokens using character offsets.

    Spans must be a list of dicts with:
    - 'start': int
    - 'end': int
    - 'type': str (e.g., 'SSN', 'EMAIL')

    Spans are processed in reverse order of start position to prevent offset drift.
    """
    if not text or not spans:
        return text

    # Sort spans in reverse order by start offset
    sorted_spans = sorted(spans, key=lambda s: s.get("start", 0), reverse=True)

    result = text
    for span in sorted_spans:
        start = int(span.get("start", 0))
        end = int(span.get("end", 0))
        entity_type = str(span.get("type", "PII"))

        if 0 <= start <= end <= len(result):
            replacement = mask_format.format(type=entity_type)
            result = result[:start] + replacement + result[end:]

    return result


def redact_text_by_values(
    text: str,
    replacements: Dict[str, str],
    case_sensitive: bool = True,
) -> str:
    """
    Replace specific text strings with replacement tokens.

    Args:
        text: Input string.
        replacements: Mapping of {raw_pii_value: replacement_token}.
        case_sensitive: Whether matching should be case-sensitive.
    """
    if not text or not replacements:
        return text

    result = text
    # Sort replacements by length descending to replace longer phrases first
    sorted_items = sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True)

    for raw_val, mask in sorted_items:
        if not raw_val or not raw_val.strip():
            continue
        flags = 0 if case_sensitive else re.IGNORECASE
        escaped = re.escape(raw_val)
        result = re.sub(escaped, mask, result, flags=flags)

    return result


def redact_text(
    text: str,
    entities: Sequence[Union[Dict, object]],
    mask_style: str = "tag",
) -> str:
    """
    Convenience redactor accepting either PIIEntity or EntityAnnotation objects.

    Args:
        text: Input text.
        entities: List of entities (PIIEntity, EntityAnnotation, or dicts).
        mask_style: "tag" for `[REDACTED:TYPE]` or "block" for `█████`.
    """
    if not text or not entities:
        return text

    replacements: Dict[str, str] = {}
    for entity in entities:
        entity_type = "PII"
        raw_val = ""

        if isinstance(entity, dict):
            entity_type = entity.get("type") or entity.get("entity_type") or "PII"
            raw_val = entity.get("value") or entity.get("raw_value") or ""
            if not raw_val and "context" in entity and isinstance(entity["context"], dict):
                raw_val = entity["context"].get("raw_value", "")
        else:
            if hasattr(entity, "type"):
                entity_type = getattr(entity, "type")
            elif hasattr(entity, "entity_type"):
                val = getattr(entity, "entity_type")
                entity_type = val.value if hasattr(val, "value") else str(val)

            if hasattr(entity, "value") and entity.value:
                raw_val = entity.value
            elif hasattr(entity, "context") and isinstance(entity.context, dict):
                raw_val = entity.context.get("raw_value", "")

        if raw_val:
            mask = f"[REDACTED:{entity_type}]" if mask_style == "tag" else "█" * max(4, len(raw_val))
            replacements[raw_val] = mask

    return redact_text_by_values(text, replacements)
