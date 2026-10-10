"""
Native Text Redactor
====================

Replaces detected PII spans in extracted text with redaction tokens.

    token mode: "SSN: 219-45-7890"  ->  "SSN: [REDACTED_SSN]"
    block mode: "SSN: 219-45-7890"  ->  "SSN: ███████████"   (same length, keeps layout)

Inputs are Person 3 entities whose text_start/text_end are offsets into the
text of the ContentBlock named by entity.block_id. Every entity whose action
is not ALLOW is redacted (redaction by default: REDACT, BLOCK, REVIEW, unknown).

Fail-closed bookkeeping: any entity that cannot be applied (no matching
block, offsets out of range) is reported in `unapplied_entity_ids`. The AI
readiness gate blocks the document when that list is not empty.

For native DOCX output, `build_docx_replacements()` produces the
{target_text: token} map consumed by Person 1's
DOCXReconstructor.replace_text_in_document().

**Ownership:** Person 4 (Security Policy, Independent Verification & Audit)
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from src.policy.risk import (
    entity_action_name,
    entity_block_id,
    entity_risk_name,
    entity_type_name,
    risk_rank,
)


@dataclass
class AppliedRedaction:
    """One merged span that was replaced. Offsets only, never the raw value."""

    entity_ids: List[str]
    entity_type: str
    original_start: int
    original_end: int
    redacted_start: int
    redacted_end: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_ids": list(self.entity_ids),
            "entity_type": self.entity_type,
            "original_span": [self.original_start, self.original_end],
            "redacted_span": [self.redacted_start, self.redacted_end],
        }


@dataclass
class TextRedactionResult:
    text: str
    applied: List[AppliedRedaction] = field(default_factory=list)
    unapplied_entity_ids: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def redaction_count(self) -> int:
        return len(self.applied)


@dataclass
class BlockRedactionResult:
    sanitized_blocks: List[Any] = field(default_factory=list)
    per_block: Dict[str, TextRedactionResult] = field(default_factory=dict)
    unapplied_entity_ids: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def redaction_count(self) -> int:
        return sum(r.redaction_count for r in self.per_block.values())

    @property
    def sanitized_text(self) -> str:
        return "\n\n".join(getattr(b, "text", "") for b in self.sanitized_blocks)

    @property
    def is_complete(self) -> bool:
        return not self.unapplied_entity_ids and not self.errors


class TextRedactor:
    """Offset-based text redaction with overlap merging."""

    def __init__(
        self,
        mode: str = "token",
        token_format: str = "[REDACTED_{type}]",
        block_char: str = "█",
        min_docx_target_length: int = 3,
    ):
        if mode not in ("token", "block"):
            raise ValueError("mode must be 'token' or 'block'")
        if not block_char:
            raise ValueError("block_char cannot be empty")
        self.mode = mode
        self.token_format = token_format
        self.block_char = block_char
        self.min_docx_target_length = min_docx_target_length

    @classmethod
    def from_policy(cls, policy: Any) -> "TextRedactor":
        """Build from a PolicyEngine or PolicyConfig (uses its `redaction` section)."""
        config = getattr(policy, "config", policy)
        settings = config.redaction
        return cls(
            mode=settings["mode"],
            token_format=settings["token_format"],
            block_char=settings["block_char"],
            min_docx_target_length=int(settings["min_docx_target_length"]),
        )

    def token_for(self, entity_type: str, length: int) -> str:
        if self.mode == "block":
            return self.block_char * max(1, length)
        return self.token_format.format(type=entity_type or "PII")

    # ------------------------------------------------------------------ core
    @staticmethod
    def _needs_redaction(entity: Any) -> bool:
        return entity_action_name(entity) != "ALLOW"

    def _collect_spans(
        self, text: str, entities: Iterable[Any]
    ) -> Tuple[List[Tuple[int, int, Any]], List[str], List[str]]:
        spans, unapplied, errors = [], [], []
        for entity in entities:
            if not self._needs_redaction(entity):
                continue
            entity_id = str(getattr(entity, "entity_id", ""))
            try:
                start = int(getattr(entity, "text_start"))
                end = int(getattr(entity, "text_end"))
            except (TypeError, ValueError, AttributeError):
                unapplied.append(entity_id)
                errors.append(f"{entity_id}: missing text offsets")
                continue
            if not 0 <= start < end <= len(text):
                unapplied.append(entity_id)
                errors.append(
                    f"{entity_id}: offsets [{start}, {end}) outside text of length {len(text)}"
                )
                continue
            spans.append((start, end, entity))
        return spans, unapplied, errors

    @staticmethod
    def _merge(spans: List[Tuple[int, int, Any]]) -> List[Tuple[int, int, List[Any]]]:
        merged: List[Tuple[int, int, List[Any]]] = []
        for start, end, entity in sorted(spans, key=lambda s: (s[0], -s[1])):
            if merged and start < merged[-1][1]:
                prev_start, prev_end, members = merged[-1]
                merged[-1] = (prev_start, max(prev_end, end), members + [entity])
            else:
                merged.append((start, end, [entity]))
        return merged

    def redact_text(self, text: str, entities: Iterable[Any]) -> TextRedactionResult:
        """Redact `entities` (offsets relative to `text`)."""
        text = text or ""
        spans, unapplied, errors = self._collect_spans(text, entities)
        result = TextRedactionResult(text=text, unapplied_entity_ids=unapplied, errors=errors)
        if not spans:
            return result

        pieces: List[str] = []
        cursor = 0
        out_len = 0
        for start, end, members in self._merge(spans):
            # Label a merged span with its highest-risk member's type.
            label_entity = max(members, key=lambda e: risk_rank(entity_risk_name(e)))
            entity_type = entity_type_name(label_entity)
            replacement = self.token_for(entity_type, end - start)

            prefix = text[cursor:start]
            pieces.append(prefix)
            out_len += len(prefix)
            pieces.append(replacement)
            result.applied.append(AppliedRedaction(
                entity_ids=[str(getattr(m, "entity_id", "")) for m in members],
                entity_type=entity_type,
                original_start=start,
                original_end=end,
                redacted_start=out_len,
                redacted_end=out_len + len(replacement),
            ))
            out_len += len(replacement)
            cursor = end

        pieces.append(text[cursor:])
        result.text = "".join(pieces)
        return result

    def redact_blocks(
        self, blocks: Sequence[Any], entities: Iterable[Any]
    ) -> BlockRedactionResult:
        """
        Redact a list of blocks (ContentBlock / ExtractedBlock: `.block_id`, `.text`).

        Returns copies; the input blocks are left untouched.
        """
        by_block: Dict[str, List[Any]] = {}
        orphan_ids: List[str] = []
        known_ids = {str(getattr(b, "block_id", "")) for b in blocks}

        for entity in entities:
            if not self._needs_redaction(entity):
                continue
            block_id = entity_block_id(entity)
            if block_id and block_id in known_ids:
                by_block.setdefault(block_id, []).append(entity)
            else:
                orphan_ids.append(str(getattr(entity, "entity_id", "")))

        result = BlockRedactionResult(unapplied_entity_ids=list(orphan_ids))
        if orphan_ids:
            result.errors.append(
                f"{len(orphan_ids)} entities reference no known block_id and could not be redacted"
            )

        for block in blocks:
            block_id = str(getattr(block, "block_id", ""))
            sanitized = copy.copy(block)
            block_entities = by_block.get(block_id, [])
            if block_entities:
                block_result = self.redact_text(getattr(block, "text", "") or "", block_entities)
                sanitized.text = block_result.text
                result.per_block[block_id] = block_result
                result.unapplied_entity_ids.extend(block_result.unapplied_entity_ids)
                result.errors.extend(block_result.errors)
            result.sanitized_blocks.append(sanitized)

        return result

    def build_docx_replacements(
        self, blocks: Sequence[Any], entities: Iterable[Any]
    ) -> Tuple[Dict[str, str], List[str]]:
        """
        Build {original_text: token} for DOCXReconstructor.replace_text_in_document().

        The map holds raw PII in memory only; never log or persist it.
        Targets shorter than `min_docx_target_length` are skipped (a global
        find/replace of "Al" would corrupt unrelated words) and returned as
        skipped entity ids so the caller can fail closed.
        """
        text_by_block = {str(getattr(b, "block_id", "")): getattr(b, "text", "") or "" for b in blocks}
        replacements: Dict[str, str] = {}
        skipped: List[str] = []

        for entity in entities:
            if not self._needs_redaction(entity):
                continue
            entity_id = str(getattr(entity, "entity_id", ""))
            text = text_by_block.get(entity_block_id(entity))
            start = getattr(entity, "text_start", None)
            end = getattr(entity, "text_end", None)
            if text is None or not isinstance(start, int) or not isinstance(end, int) \
                    or not 0 <= start < end <= len(text):
                skipped.append(entity_id)
                continue
            target = text[start:end]
            if len(target.strip()) < self.min_docx_target_length:
                skipped.append(entity_id)
                continue
            replacements[target] = self.token_for(entity_type_name(entity), len(target))

        return replacements, skipped


def redact_text(
    text: str, entities: Iterable[Any], mode: str = "token"
) -> TextRedactionResult:
    """Module-level convenience wrapper."""
    return TextRedactor(mode=mode).redact_text(text, entities)
