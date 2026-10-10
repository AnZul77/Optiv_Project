"""
Unit Tests: Native Text Redactor (Person 4)
"""

from types import SimpleNamespace

import pytest

from src.sanitization.text_redactor import TextRedactor
from src.schema.entities import Action, ContentBlock, EntityType, PIIEntity

TEXT = "Name: Alice Vance, SSN: 219-45-7890, mail alice@corp.com"


def _entity(etype, start, end, block_id="b1", action=Action.REDACT):
    return PIIEntity(entity_type=etype, value=TEXT[start:end], text_start=start, text_end=end,
                     block_id=block_id, confidence=0.9, page=1, action=action)


@pytest.fixture
def entities():
    return [
        _entity(EntityType.PERSON, 6, 17),
        _entity(EntityType.SSN, 24, 35),
        _entity(EntityType.EMAIL, 42, 56),
    ]


class TestRedactText:
    def test_token_mode(self, entities):
        result = TextRedactor().redact_text(TEXT, entities)
        assert result.text == "Name: [REDACTED_PERSON], SSN: [REDACTED_SSN], mail [REDACTED_EMAIL]"
        assert result.redaction_count == 3
        assert not result.unapplied_entity_ids

    def test_block_mode_preserves_length(self, entities):
        result = TextRedactor(mode="block").redact_text(TEXT, entities)
        assert len(result.text) == len(TEXT)
        assert "219-45-7890" not in result.text
        assert "█" * 11 in result.text

    def test_redacted_offsets_point_at_tokens(self, entities):
        result = TextRedactor().redact_text(TEXT, entities)
        for applied in result.applied:
            token = result.text[applied.redacted_start:applied.redacted_end]
            assert token == f"[REDACTED_{applied.entity_type}]"

    def test_allow_listed_entities_untouched(self):
        e = _entity(EntityType.EMPLOYEE_ID, 0, 4, action=Action.ALLOW)
        assert TextRedactor().redact_text(TEXT, [e]).text == TEXT

    def test_blocked_and_review_entities_still_redacted(self):
        block = _entity(EntityType.SSN, 24, 35, action=Action.BLOCK)
        review = _entity(EntityType.EMAIL, 42, 56, action=Action.REVIEW)
        out = TextRedactor().redact_text(TEXT, [block, review]).text
        assert "219-45-7890" not in out and "alice@corp.com" not in out

    def test_overlaps_merge_and_take_highest_risk_label(self):
        person = _entity(EntityType.PERSON, 20, 35)   # overlaps the SSN
        ssn = _entity(EntityType.SSN, 24, 35)
        result = TextRedactor().redact_text(TEXT, [person, ssn])
        assert result.redaction_count == 1
        assert result.applied[0].entity_type == "SSN"
        assert set(result.applied[0].entity_ids) == {person.entity_id, ssn.entity_id}

    @pytest.mark.parametrize("start,end", [(-1, 4), (50, 999), (10, 10), (12, 5)])
    def test_bad_offsets_reported_not_ignored(self, start, end):
        e = _entity(EntityType.SSN, 0, 1)
        e.text_start, e.text_end = start, end
        result = TextRedactor().redact_text(TEXT, [e])
        assert result.unapplied_entity_ids == [e.entity_id]
        assert result.errors

    def test_annotation_style_entities_supported(self):
        ann = SimpleNamespace(entity_id="a1", type="SSN", risk="CRITICAL", action="REDACT",
                              text_start=24, text_end=35)
        assert "[REDACTED_SSN]" in TextRedactor().redact_text(TEXT, [ann]).text

    def test_invalid_mode(self):
        with pytest.raises(ValueError):
            TextRedactor(mode="blur")


class TestRedactBlocks:
    def test_blocks_redacted_by_block_id_and_inputs_untouched(self, entities):
        blocks = [ContentBlock(text=TEXT, block_id="b1", page=1),
                  ContentBlock(text="nothing here", block_id="b2", page=1)]
        result = TextRedactor().redact_blocks(blocks, entities)
        assert result.is_complete
        assert "[REDACTED_SSN]" in result.sanitized_blocks[0].text
        assert result.sanitized_blocks[1].text == "nothing here"
        assert blocks[0].text == TEXT
        assert "[REDACTED_EMAIL]" in result.sanitized_text

    def test_orphan_entities_reported(self):
        orphan = _entity(EntityType.SSN, 24, 35, block_id="missing")
        result = TextRedactor().redact_blocks([ContentBlock(text=TEXT, block_id="b1")], [orphan])
        assert result.unapplied_entity_ids == [orphan.entity_id]
        assert not result.is_complete

    def test_block_id_read_from_annotation_context(self):
        ann = SimpleNamespace(entity_id="a1", type="SSN", risk="CRITICAL", action="REDACT",
                              text_start=24, text_end=35, context={"block_id": "b1"})
        result = TextRedactor().redact_blocks([ContentBlock(text=TEXT, block_id="b1")], [ann])
        assert result.is_complete


class TestDocxReplacements:
    def test_map_for_docx_reconstructor(self, entities):
        blocks = [ContentBlock(text=TEXT, block_id="b1")]
        replacements, skipped = TextRedactor().build_docx_replacements(blocks, entities)
        assert replacements["219-45-7890"] == "[REDACTED_SSN]"
        assert replacements["alice@corp.com"] == "[REDACTED_EMAIL]"
        assert not skipped

    def test_short_targets_skipped(self):
        short = _entity(EntityType.PERSON, 0, 2)
        _, skipped = TextRedactor().build_docx_replacements([ContentBlock(text=TEXT, block_id="b1")], [short])
        assert skipped == [short.entity_id]

    def test_feeds_person1_docx_reconstructor(self, tmp_path, entities):
        docx = pytest.importorskip("docx")
        from src.sanitization.docx_reconstructor import DOCXReconstructor

        src, out = tmp_path / "in.docx", tmp_path / "out.docx"
        document = docx.Document()
        document.add_paragraph(TEXT)
        document.save(src)

        replacements, _ = TextRedactor().build_docx_replacements(
            [ContentBlock(text=TEXT, block_id="b1")], entities
        )
        ok, err = DOCXReconstructor.replace_text_in_document(str(src), str(out), replacements)
        assert ok, err
        text = "\n".join(p.text for p in docx.Document(out).paragraphs)
        assert "219-45-7890" not in text and "[REDACTED_SSN]" in text
