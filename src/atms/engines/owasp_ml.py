"""OWASP ML Top 10 (2023) enrichment (v0.13 — v0.17.2 Cycle B wrapper).

Now a thin wrapper around `engines.frameworks.enrich_with_frameworks`
using the `OWASP_ML_SPEC` single-spec registry. Behavior is byte-
identical to the pre-Cycle-B engine.
"""

from __future__ import annotations

from ..kb import KnowledgeBase
from ..models import Component, Threat
from .frameworks import OWASP_ML_SPEC, enrich_with_frameworks


def enrich_with_owasp_ml(
    threats: list[Threat],
    components: list[Component],
    kb: KnowledgeBase | None = None,
    max_per_threat: int = 2,
) -> list[Threat]:
    spec = OWASP_ML_SPEC if max_per_threat == OWASP_ML_SPEC.max_per_threat else \
           OWASP_ML_SPEC.__class__(**{**OWASP_ML_SPEC.__dict__,
                                      "max_per_threat": max_per_threat})
    return enrich_with_frameworks(threats, components, kb=kb, registry=(spec,))


__all__ = ["enrich_with_owasp_ml"]
