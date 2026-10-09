"""
Entity Resolver (Layer 5)
=========================

Overlapping span merging, deduplication, and conflict resolution across
all detection layers (Regex, NER, Context, Validator).

When multiple detection layers flag the same text span (or overlapping spans),
the resolver merges them into a single canonical entity with:
    - Combined detection_layers from all sources
    - Highest confidence score
    - Most specific entity type
    - Combined context cues

Resolution Rules:
    1. Overlap Detection:  Two entities overlap if [text_start, text_end)
       ranges intersect on the same block_id.
    2. Merge Strategy:     Keep highest confidence, combine layers & cues,
       use most specific entity type.
    3. Type Conflict:      CRITICAL > HIGH > MEDIUM > LOW risk entities win.
    4. Deduplication:      After resolution, entities with identical
       (block_id, text_start, text_end, entity_type) are collapsed.

**Ownership:** Person 3 (PII Detection & Context Engine Lead)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from src.schema.entities import (
    PIIEntity,
    EntityType,
    RiskLevel,
    RISK_MAPPING,
    DEFAULT_RISK_LEVEL,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Risk Priority (for type conflict resolution)
# =============================================================================

RISK_PRIORITY = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.HIGH: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 3,
}

# Entity type specificity — more specific types win in conflicts
# Lower number = more specific / higher priority
TYPE_SPECIFICITY: Dict[EntityType, int] = {
    # Critical IDs — very specific patterns
    EntityType.SSN: 1,
    EntityType.PASSPORT: 2,
    EntityType.PAN: 3,
    EntityType.AADHAAR: 4,
    EntityType.CARD: 5,
    EntityType.NINO: 6,
    # High-risk — moderately specific
    EntityType.EMAIL: 10,
    EntityType.PHONE: 11,
    EntityType.EMPLOYEE_ID: 12,
    EntityType.DIRECTOR_ID: 13,
    EntityType.DOB: 14,
    EntityType.BANK_ACCOUNT: 15,
    EntityType.TAX_ID: 16,
    # Medium-risk
    EntityType.IFSC: 20,
    EntityType.GST: 21,
    EntityType.UPI: 22,
    # Broad / generic
    EntityType.PERSON: 30,
    EntityType.ADDRESS: 31,
    EntityType.SIGNATURE: 40,
    EntityType.FACE_PHOTO: 41,
    EntityType.SENSITIVE_SCREENSHOT: 42,
}


class EntityResolver:
    """
    Layer 5: Merge overlapping spans and deduplicate across detection layers.

    This is the final step before entities are sent to the Policy Engine (P4).
    It ensures each text region has exactly one canonical entity.
    """

    def __init__(self, overlap_threshold: float = 0.3):
        """
        Initialize the Entity Resolver.

        Args:
            overlap_threshold: Minimum overlap ratio (IoU) to consider two
                               entities as overlapping. Default 0.3 (30%).
        """
        self.overlap_threshold = overlap_threshold

    def resolve(self, entities: List[PIIEntity]) -> List[PIIEntity]:
        """
        Merge overlapping entities and deduplicate.

        Pipeline:
            1. Group entities by block_id
            2. Within each block, find overlapping groups
            3. Merge each overlapping group into one entity
            4. Deduplicate identical entities

        Args:
            entities: Raw entities from all detection layers.

        Returns:
            Resolved and deduplicated entity list.
        """
        if not entities:
            return []

        initial_count = len(entities)

        # Step 1: Group by block_id
        block_groups: Dict[str, List[PIIEntity]] = defaultdict(list)
        for entity in entities:
            block_groups[entity.block_id].append(entity)

        # Step 2: Resolve within each block
        resolved: List[PIIEntity] = []
        merge_count = 0

        for block_id, block_entities in block_groups.items():
            # Sort by text_start for efficient overlap detection
            block_entities.sort(key=lambda e: (e.text_start, e.text_end))

            # Find overlapping groups
            overlap_groups = self._find_overlapping_groups(block_entities)

            for group in overlap_groups:
                if len(group) == 1:
                    resolved.append(group[0])
                else:
                    merged = self._merge_group(group)
                    resolved.append(merged)
                    merge_count += len(group) - 1

        # Step 3: Deduplicate
        dedup_count = len(resolved)
        resolved = self._deduplicate(resolved)
        dedup_count = dedup_count - len(resolved)

        logger.info(
            "EntityResolver: %d input → %d resolved (%d merges, %d dedup removals)",
            initial_count, len(resolved), merge_count, dedup_count,
        )

        return resolved

    def _find_overlapping_groups(
        self, entities: List[PIIEntity]
    ) -> List[List[PIIEntity]]:
        """
        Group entities with overlapping text spans.

        Uses a sweep-line approach on sorted entities:
            - Maintain active entities (those whose span hasn't ended)
            - When a new entity overlaps with any active entity, group them
            - Uses Union-Find for efficient grouping

        Args:
            entities: Entities sorted by text_start.

        Returns:
            List of groups (each group is a list of overlapping entities).
        """
        if not entities:
            return []

        n = len(entities)
        # Union-Find parent array
        parent = list(range(n))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]  # Path compression
                x = parent[x]
            return x

        def union(x: int, y: int) -> None:
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        # Find overlaps using the sweep-line
        for i in range(n):
            for j in range(i + 1, n):
                # Since sorted by text_start, if j starts after i ends, no more overlaps
                if entities[j].text_start >= entities[i].text_end:
                    break

                # Check if they truly overlap (with threshold)
                if self._spans_overlap(entities[i], entities[j]):
                    union(i, j)

        # Group by root parent
        groups: Dict[int, List[PIIEntity]] = defaultdict(list)
        for i in range(n):
            root = find(i)
            groups[root].append(entities[i])

        return list(groups.values())

    def _spans_overlap(self, a: PIIEntity, b: PIIEntity) -> bool:
        """
        Check if two entities have overlapping text spans.

        Uses Intersection over Union (IoU) with a configurable threshold.
        """
        # Calculate intersection
        inter_start = max(a.text_start, b.text_start)
        inter_end = min(a.text_end, b.text_end)

        if inter_start >= inter_end:
            return False  # No intersection

        intersection = inter_end - inter_start

        # Calculate union
        union = (a.text_end - a.text_start) + (b.text_end - b.text_start) - intersection

        if union <= 0:
            return False

        iou = intersection / union
        return iou >= self.overlap_threshold

    def _merge_group(self, group: List[PIIEntity]) -> PIIEntity:
        """
        Merge a group of overlapping entities into a single entity.

        Strategy:
            - Entity type: Most specific (lowest TYPE_SPECIFICITY) or highest risk
            - Confidence: Maximum across all group members
            - Detection layers: Union of all layers
            - Context cues: Union of all cues
            - Span: Covers the full range of all overlapping spans
            - Validator result: First non-NOT_APPLICABLE result
            - Bbox: First available bounding box
        """
        if len(group) == 1:
            return group[0]

        # Determine best entity type (most specific + highest risk)
        best_type = self._resolve_type_conflict(
            [e.entity_type for e in group]
        )

        # Find the entity with highest confidence for base values
        best_entity = max(group, key=lambda e: e.confidence)

        # Combine all detection layers
        all_layers: Set[str] = set()
        for e in group:
            all_layers.update(e.detection_layers)

        # Combine all context cues
        all_cues: Set[str] = set()
        for e in group:
            all_cues.update(e.context_cues)

        # Find widest span
        min_start = min(e.text_start for e in group)
        max_end = max(e.text_end for e in group)

        # Get the best value (from highest confidence entity)
        best_value = best_entity.value

        # Get first non-NA validator result
        from src.schema.entities import ValidatorStatus
        validator_result = ValidatorStatus.NOT_APPLICABLE
        for e in group:
            if e.validator_result != ValidatorStatus.NOT_APPLICABLE:
                validator_result = e.validator_result
                break

        # Get first available bbox
        bbox = None
        for e in group:
            if e.bbox is not None:
                bbox = e.bbox
                break

        merged = PIIEntity(
            entity_type=best_type,
            value=best_value,
            source=best_entity.source,
            detection_layers=sorted(list(all_layers)),
            confidence=max(e.confidence for e in group),
            page=best_entity.page,
            bbox=bbox,
            text_start=min_start,
            text_end=max_end,
            block_id=best_entity.block_id,
            context_cues=sorted(list(all_cues)),
            validator_result=validator_result,
        )

        logger.debug(
            "Merged %d entities into one: type=%s, confidence=%.2f, "
            "layers=%s, span=[%d:%d]",
            len(group), best_type.value, merged.confidence,
            merged.detection_layers, min_start, max_end,
        )

        return merged

    def _resolve_type_conflict(self, types: List[EntityType]) -> EntityType:
        """
        When overlapping entities have different types, pick the best.

        Priority:
            1. Higher risk level (CRITICAL > HIGH > MEDIUM > LOW)
            2. More specific type (lower TYPE_SPECIFICITY number)
        """
        if not types:
            return EntityType.PERSON  # Fallback

        if len(set(types)) == 1:
            return types[0]

        # Sort by risk priority (ascending = higher priority), then specificity
        def sort_key(t: EntityType) -> Tuple[int, int]:
            risk = RISK_MAPPING.get(t, DEFAULT_RISK_LEVEL)
            risk_priority = RISK_PRIORITY.get(risk, 99)
            specificity = TYPE_SPECIFICITY.get(t, 50)
            return (risk_priority, specificity)

        return sorted(set(types), key=sort_key)[0]

    def _deduplicate(self, entities: List[PIIEntity]) -> List[PIIEntity]:
        """
        Remove exact duplicates — entities with the same
        (block_id, text_start, text_end, entity_type) tuple.

        When duplicates exist, keep the one with higher confidence.
        """
        seen: Dict[Tuple[str, int, int, str], PIIEntity] = {}

        for entity in entities:
            key = (
                entity.block_id,
                entity.text_start,
                entity.text_end,
                entity.entity_type.value,
            )

            if key in seen:
                existing = seen[key]
                if entity.confidence > existing.confidence:
                    # Keep higher confidence, but merge layers
                    entity.detection_layers = sorted(
                        set(entity.detection_layers + existing.detection_layers)
                    )
                    entity.context_cues = sorted(
                        set(entity.context_cues + existing.context_cues)
                    )
                    seen[key] = entity
                else:
                    # Keep existing, merge in new layers
                    existing.detection_layers = sorted(
                        set(existing.detection_layers + entity.detection_layers)
                    )
                    existing.context_cues = sorted(
                        set(existing.context_cues + entity.context_cues)
                    )
            else:
                seen[key] = entity

        return list(seen.values())
