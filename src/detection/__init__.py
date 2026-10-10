"""
PII Detection Engine Package
=============================

Core multi-layered PII detection engine:
- Layer 1: RegexEngine (Deterministic pattern matching + allow-list)
- Layer 2: NEREngine (Presidio + spaCy ML extraction)
- Layer 3: ContextEngine (Document & table-level structural reasoning)
- Layer 4: ValidatorEngine (Algorithmic checksums & validations)
- Layer 5: EntityResolver (Union-Find span merging & conflict resolution)

Pipeline Orchestrator:
- DetectionPipeline: Unified runner with ablation toggles

Ownership: Person 3 (PII Detection & Context Engine Lead)
"""

from src.detection.regex import RegexEngine
from src.detection.ner import NEREngine
from src.detection.context import ContextEngine
from src.detection.validators import ValidatorEngine
from src.detection.resolver import EntityResolver
from src.detection.pipeline import DetectionPipeline

__all__ = [
    "RegexEngine",
    "NEREngine",
    "ContextEngine",
    "ValidatorEngine",
    "EntityResolver",
    "DetectionPipeline",
]
