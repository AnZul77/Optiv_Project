import pytest
from src.sanitization.text_redactor import (
    redact_text_by_spans,
    redact_text_by_values,
    redact_text,
)


def test_redact_text_by_spans():
    text = "Contact Alice at alice@example.com or call 555-0199."
    spans = [
        {"start": 8, "end": 13, "type": "PERSON"},
        {"start": 17, "end": 34, "type": "EMAIL"},
        {"start": 43, "end": 51, "type": "PHONE"},
    ]
    redacted = redact_text_by_spans(text, spans)
    assert "[REDACTED:PERSON]" in redacted
    assert "[REDACTED:EMAIL]" in redacted
    assert "[REDACTED:PHONE]" in redacted
    assert "alice@example.com" not in redacted
    assert "Alice" not in redacted


def test_redact_text_by_values():
    text = "Employee John Doe with SSN 123-45-6789 and email john@doe.com."
    replacements = {
        "John Doe": "[REDACTED:PERSON]",
        "123-45-6789": "[REDACTED:SSN]",
        "john@doe.com": "[REDACTED:EMAIL]",
    }
    redacted = redact_text_by_values(text, replacements)
    assert "[REDACTED:PERSON]" in redacted
    assert "[REDACTED:SSN]" in redacted
    assert "[REDACTED:EMAIL]" in redacted
    assert "John Doe" not in redacted


def test_redact_text_convenience():
    from src.schema.entities import PIIEntity, EntityType
    text = "Director Robert Smith submitted report."
    entity = PIIEntity(
        entity_type=EntityType.PERSON,
        value="Robert Smith",
        confidence=0.9,
    )
    redacted = redact_text(text, [entity])
    assert "[REDACTED:PERSON]" in redacted
    assert "Robert Smith" not in redacted
