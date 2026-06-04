"""LINDDUN privacy enrichment (v0.10 — v0.17.2 Cycle B wrapper).

Now a thin wrapper around `engines.frameworks.enrich_with_frameworks`
using the `LINDDUN_SPEC` single-spec registry. Behavior is byte-
identical to the pre-Cycle-B engine.

The original 76-line implementation is preserved in commit history
(pre-v0.17.2). The `FrameworkSpec` registry in `engines.frameworks`
captures the exact same bonus rules, threshold, and tokenisation
choices as a declarative dataclass instance.
"""

from __future__ import annotations

from ..kb import KnowledgeBase
from ..models import Component, Threat
from .frameworks import LINDDUN_SPEC, enrich_with_frameworks


def enrich_with_linddun(
    threats: list[Threat],
    components: list[Component],
    kb: KnowledgeBase | None = None,
    max_per_threat: int = 3,
) -> list[Threat]:
    """Back-compat wrapper. `max_per_threat` is read off LINDDUN_SPEC
    unless overridden; the parameter is retained for callers that
    pass it explicitly."""
    spec = LINDDUN_SPEC if max_per_threat == LINDDUN_SPEC.max_per_threat else \
           LINDDUN_SPEC.__class__(**{**LINDDUN_SPEC.__dict__,
                                     "max_per_threat": max_per_threat})
    return enrich_with_frameworks(threats, components, kb=kb, registry=(spec,))


__all__ = ["enrich_with_linddun"]
