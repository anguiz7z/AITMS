"""Compliance-control enrichment (v0.13).

Maps each threat to the regulatory / framework controls it relates to,
based on component type + keyword overlap + STRIDE-AI alignment, the
same pattern as `engines/cloud.py` and `engines/linddun.py`. Adds IDs
to ``Threat.compliance_controls`` (additive, never removes).

Frameworks bundled in `kb/compliance/controls.yaml`:
NIS2, DORA, EU AI Act, GDPR, PCI DSS v4.0, HIPAA, NIST 800-53 r5,
NIST CSF 2.0, ISO 27001:2022, SEC cybersecurity disclosure.
"""

from __future__ import annotations

import re

from ..kb import KnowledgeBase, get_kb
from ..models import Component, System, Threat

__all__ = ["enrich_with_compliance"]


def enrich_with_compliance(
    threats: list[Threat],
    components: list[Component],
    kb: KnowledgeBase | None = None,
    max_per_threat: int = 4,
    system: System | None = None,
) -> list[Threat]:
    kb = kb or get_kb()
    if not kb.compliance_controls:
        return threats
    comp_by_id = {c.id: c for c in components}

    # v0.16.3 — EU AI Act gate. Article 14 ("Human Oversight") + 13
    # ("Transparency") only bind on Annex-III high-risk AI systems.
    # When the system isn't flagged, we drop EU_AI_ACT controls from
    # candidates. Avoid stamping the register with regulator-attractive
    # IDs that wouldn't survive a desk review.
    is_high_risk_eu = bool(
        system is not None and getattr(system, "is_high_risk_under_eu_ai_act", False)
    )
    # v0.16.9 (Bug-015): gate ALL EU_AI_ACT IDs (including .50) when the
    # system isn't flagged as high-risk. Article 50 transparency
    # obligations apply only to limited/high-risk; we don't try to
    # discriminate further — when in doubt, omit, per the model-field
    # docstring contract.

    for threat in threats:
        comp = comp_by_id.get(threat.component_id)
        if comp is None:
            continue
        haystack = (threat.title + " " + threat.description).lower()

        scored: list[tuple[str, int]] = []
        for control_id, ctrl in kb.compliance_controls.items():
            if control_id in threat.compliance_controls:
                continue
            applies = set(ctrl.get("applies_to", []))
            if applies and comp.type not in applies:
                continue
            score = 0
            # Substring keyword match is more forgiving than token overlap —
            # "phish" must match "phishing", "ransom" must match "ransomware".
            for kw in ctrl.get("keywords", []) or []:
                if not isinstance(kw, str) or len(kw) < 3:
                    continue
                if kw.lower() in haystack:
                    # Multi-word keywords are stronger signals.
                    score += 2 if " " in kw else 1
            # Title tokens add to score when one or more meaningful words appear
            for tok in re.findall(r"[a-zA-Z]{4,}", str(ctrl.get("title", "")).lower()):
                if tok in haystack:
                    score += 1
                    break
            stride_match = bool(set(ctrl.get("stride_ai", [])) & set(threat.stride_ai))
            if stride_match:
                score += 2
            # Component-type match alone is weak; require at least one keyword
            # / title hit unless STRIDE aligns explicitly.
            if score >= 1 and (any(kw in haystack for kw in (ctrl.get("keywords") or []) if isinstance(kw, str)) or stride_match):
                scored.append((control_id, score))

        scored.sort(key=lambda t: t[1], reverse=True)
        for control_id, _ in scored[:max_per_threat]:
            if control_id not in threat.compliance_controls:
                # v0.16.3+v0.16.9 — suppress EU AI Act controls when not high-risk.
                # Match by prefix to catch .13/.14/.15/.50 alike.
                if not is_high_risk_eu and control_id.startswith("EU_AI_ACT"):
                    continue
                threat.compliance_controls.append(control_id)

    return threats


__all__ = ["enrich_with_compliance"]
