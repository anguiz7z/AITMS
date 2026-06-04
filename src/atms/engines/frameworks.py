"""Unified framework-enrichment engine (v0.17.2 Cycle B).

Closes architectural-review finding C3: four framework-enrichment
engines (`mapping.enrich_with_atlas`, `linddun.enrich_with_linddun`,
`nist_ai_100_2.enrich_with_nist_ai_100_2`,
`owasp_ml.enrich_with_owasp_ml`) shared an identical 30-line skeleton
and differed only in four axes:

  1. Which KB dict they read (`kb.atlas_techniques`, `kb.linddun`,
     `kb.nist_ai_100_2`, `kb.owasp_ml`).
  2. Which `Threat.<field>` list they appended to.
  3. Which entry fields they tokenised (always `keywords`; some also
     `title` and/or `short`).
  4. Bonus rules (LINDDUN: +1 if privacy hint in threat text; NIST:
     stride×family alignment bonuses; others: none).

This module declares a `FrameworkSpec` registry capturing those four
axes as data. One `enrich_with_frameworks(...)` function consumes the
registry and runs all framework matches in a single pass. The four
original modules become thin wrappers (back-compat for any callers
who import them) that delegate to the unified engine with a
single-spec registry — keeping `workflow.py:analyze()` unchanged.

Adding a new framework is now a `FrameworkSpec(...)` entry, not a new
30-line engine file. ~90 lines of net reduction across the four
engines, plus much better extensibility.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from ..kb import KnowledgeBase, get_kb
from ..models import Component, Threat

_TOKEN_RE = re.compile(r"[a-zA-Z]+")


def _tokenize(text: object) -> set[str]:
    if text is None:
        return set()
    return set(_TOKEN_RE.findall(str(text).lower()))


@dataclass(frozen=True)
class FrameworkSpec:
    """Per-framework configuration for the unified enrichment engine.

    Attributes:
        name: human-readable framework name (for logging / debugging).
        kb_attr: attribute on `KnowledgeBase` holding the entry dict
            (e.g. ``"linddun"`` → ``kb.linddun``).
        threat_field: attribute on `Threat` that holds the list of
            applied IDs for this framework (e.g. ``"linddun"`` →
            ``threat.linddun``).
        max_per_threat: cap on additions per threat per call.
        threshold: minimum overlap score for an entry to qualify.
        tokenize_entry_fields: which fields on each KB entry to tokenise
            and merge into the kw-token set. ATLAS uses
            ``("keywords",)``; LINDDUN uses
            ``("keywords", "title", "short")``.
        keyword_bonus_tokens: if ANY of these tokens appears in the
            threat's tokens, add +1 once. Used by LINDDUN's privacy-
            hint bonus.
        family_stride_bonus: tuples of
            ``(entry.family, stride_category, bonus_amount)``.
            If the KB entry's ``family`` field matches and the threat
            carries ``stride_category`` in its ``stride_ai`` list, the
            bonus is added. Used by NIST AI 100-2's family alignment.
    """

    name: str
    kb_attr: str
    threat_field: str
    max_per_threat: int = 2
    threshold: int = 2
    tokenize_entry_fields: tuple[str, ...] = ("keywords",)
    keyword_bonus_tokens: tuple[str, ...] = ()
    family_stride_bonus: tuple[tuple[str, str, int], ...] = ()


# ────────────────────────────────────────────────────────────────────
# FRAMEWORK_REGISTRY — declarative source-of-truth for the four
# engines this cycle consolidates. The bonus rules + tokenisation
# choices are preserved exactly so behavior is byte-identical to the
# pre-Cycle-B engines.
# ────────────────────────────────────────────────────────────────────

ATLAS_SPEC = FrameworkSpec(
    name="MITRE ATLAS",
    kb_attr="atlas_techniques",
    threat_field="atlas_techniques",
    max_per_threat=3,
    threshold=2,
    tokenize_entry_fields=("keywords",),
)

LINDDUN_SPEC = FrameworkSpec(
    name="LINDDUN",
    kb_attr="linddun",
    threat_field="linddun",
    max_per_threat=3,
    threshold=2,
    tokenize_entry_fields=("keywords", "title", "short"),
    keyword_bonus_tokens=("privacy", "personal", "pii", "consent", "gdpr"),
)

NIST_AI_100_2_SPEC = FrameworkSpec(
    name="NIST AI 100-2",
    kb_attr="nist_ai_100_2",
    threat_field="nist_ai_100_2",
    max_per_threat=2,
    threshold=2,
    tokenize_entry_fields=("keywords", "title"),
    family_stride_bonus=(
        ("Privacy", "Information_Disclosure", 1),
        ("Poisoning", "Tampering", 1),
        ("Evasion", "Defense_Evasion", 2),
    ),
)

OWASP_ML_SPEC = FrameworkSpec(
    name="OWASP ML 2023",
    kb_attr="owasp_ml",
    threat_field="owasp_ml",
    max_per_threat=2,
    threshold=2,
    tokenize_entry_fields=("keywords", "title"),
)

FRAMEWORK_REGISTRY: tuple[FrameworkSpec, ...] = (
    ATLAS_SPEC, LINDDUN_SPEC, NIST_AI_100_2_SPEC, OWASP_ML_SPEC,
)


def _apply_spec(
    spec: FrameworkSpec,
    threats: list[Threat],
    comp_by_id: dict[str, Component],
    kb: KnowledgeBase,
) -> None:
    """Mutate `threats` in place, adding IDs per `spec`."""
    kb_dict = getattr(kb, spec.kb_attr, None) or {}
    if not kb_dict:
        return

    for threat in threats:
        comp = comp_by_id.get(threat.component_id)
        if comp is None:
            continue
        existing = getattr(threat, spec.threat_field)
        threat_tokens = _tokenize(threat.title + " " + threat.description)

        scored: list[tuple[str, int]] = []
        for entry_id, entry in kb_dict.items():
            if entry_id in existing:
                continue
            applies = set(entry.get("applies_to", []))
            if applies and comp.type not in applies:
                continue

            kw_tokens: set[str] = set()
            for field_name in spec.tokenize_entry_fields:
                value = entry.get(field_name)
                if isinstance(value, list):
                    for item in value:
                        kw_tokens.update(_tokenize(item))
                else:
                    kw_tokens.update(_tokenize(value))

            overlap = len(threat_tokens & kw_tokens)

            # Keyword-bonus tokens: +1 once if any present in threat.
            if spec.keyword_bonus_tokens and any(
                tok in threat_tokens for tok in spec.keyword_bonus_tokens
            ):
                overlap += 1

            # Family × STRIDE alignment bonus (used by NIST).
            if spec.family_stride_bonus:
                family = entry.get("family", "")
                for f_name, stride_cat, bonus in spec.family_stride_bonus:
                    if family == f_name and stride_cat in threat.stride_ai:
                        overlap += bonus

            if overlap >= spec.threshold:
                scored.append((entry_id, overlap))

        scored.sort(key=lambda t: t[1], reverse=True)
        for entry_id, _ in scored[: spec.max_per_threat]:
            if entry_id not in existing:
                existing.append(entry_id)


def enrich_with_frameworks(
    threats: list[Threat],
    components: list[Component],
    kb: KnowledgeBase | None = None,
    registry: Iterable[FrameworkSpec] = FRAMEWORK_REGISTRY,
) -> list[Threat]:
    """Apply every framework spec in `registry` to every threat.

    Mutates threats in place; also returns them for chained-call
    compatibility with the legacy single-engine functions.
    """
    kb = kb or get_kb()
    comp_by_id = {c.id: c for c in components}
    for spec in registry:
        _apply_spec(spec, threats, comp_by_id, kb)
    return threats


__all__ = [
    "FrameworkSpec",
    "FRAMEWORK_REGISTRY",
    "ATLAS_SPEC",
    "LINDDUN_SPEC",
    "NIST_AI_100_2_SPEC",
    "OWASP_ML_SPEC",
    "enrich_with_frameworks",
]
