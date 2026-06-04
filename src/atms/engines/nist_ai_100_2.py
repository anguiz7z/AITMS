"""NIST AI 100-2 adversarial-ML enrichment (v0.11 — v0.17.2 Cycle B wrapper).

Now a thin wrapper around `engines.frameworks.enrich_with_frameworks`
using the `NIST_AI_100_2_SPEC` single-spec registry. Behavior is byte-
identical to the pre-Cycle-B engine, including the family×STRIDE
alignment bonuses (Privacy×Info_Disclosure +1, Poisoning×Tampering +1,
Evasion×Defense_Evasion +2).
"""

from __future__ import annotations

from ..kb import KnowledgeBase
from ..models import Component, Threat
from .frameworks import NIST_AI_100_2_SPEC, enrich_with_frameworks


def enrich_with_nist_ai_100_2(
    threats: list[Threat],
    components: list[Component],
    kb: KnowledgeBase | None = None,
    max_per_threat: int = 2,
) -> list[Threat]:
    spec = NIST_AI_100_2_SPEC if max_per_threat == NIST_AI_100_2_SPEC.max_per_threat else \
           NIST_AI_100_2_SPEC.__class__(**{**NIST_AI_100_2_SPEC.__dict__,
                                           "max_per_threat": max_per_threat})
    return enrich_with_frameworks(threats, components, kb=kb, registry=(spec,))


__all__ = ["enrich_with_nist_ai_100_2"]
