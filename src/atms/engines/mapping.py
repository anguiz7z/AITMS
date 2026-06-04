"""MITRE ATLAS enrichment (v0.17.2 Cycle B wrapper).

Originally a standalone engine that suggested extra ATLAS technique
IDs based on keyword overlap. Now a thin wrapper around
`engines.frameworks.enrich_with_frameworks` using the `ATLAS_SPEC`
single-spec registry. Behavior is byte-identical to the pre-Cycle-B
engine — ATLAS spec tokenises only the entry's ``keywords`` field
(not title / short), preserving the original heuristic.
"""

from __future__ import annotations

from ..kb import KnowledgeBase
from ..models import Component, Threat
from .frameworks import ATLAS_SPEC, enrich_with_frameworks


def enrich_with_atlas(
    threats: list[Threat],
    components: list[Component],
    kb: KnowledgeBase | None = None,
) -> list[Threat]:
    return enrich_with_frameworks(threats, components, kb=kb, registry=(ATLAS_SPEC,))


__all__ = ["enrich_with_atlas"]
