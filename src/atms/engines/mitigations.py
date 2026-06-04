"""Mitigation collection engine.

For each threat, collect:
  - Mitigations described inline in the playbook entry (free-text bullets)
  - ATLAS Mitigation entries referenced via the playbook's `refs` field
  - OWASP LLM Top 10 mitigations bundled with the OWASP entry

Deduplicates and ranks by "addresses" count + risk_reduction. Pure Python.
"""

from __future__ import annotations

from ..kb import KnowledgeBase, get_kb
from ..models import Component, Mitigation, Threat  # noqa: F401  (Threat used in helpers)
from ._ids import stable_id


def collect_mitigations(
    threats: list[Threat],
    components: list[Component],
    kb: KnowledgeBase | None = None,
) -> list[Mitigation]:
    kb = kb or get_kb()
    comp_type_by_id = {c.id: c.type for c in components}
    mits_by_key: dict[str, Mitigation] = {}

    for threat in threats:
        comp_type = comp_type_by_id.get(threat.component_id)
        playbook = kb.get_playbook(comp_type) if comp_type else None
        # Threat IDs follow "<component_id>.<playbook_threat_local_id>"
        local_id = threat.id.split(".", 1)[-1]

        # 1. Inline mitigations from playbook
        if playbook:
            for raw in playbook.get("threats", []):
                if raw.get("id") != local_id:
                    continue
                for mit_text in raw.get("mitigations", []):
                    title = mit_text.split(":")[0][:80] if ":" in mit_text else mit_text[:80]
                    key = f"INL:{title.lower()}"
                    m = mits_by_key.setdefault(
                        key,
                        Mitigation(
                            id=stable_id("MIT", key),
                            title=title,
                            description=mit_text,
                            framework_refs=[],
                            effort="medium",
                            risk_reduction=3,
                        ),
                    )
                    if threat.id not in m.addresses_threat_ids:
                        m.addresses_threat_ids.append(threat.id)

        # 2. ATLAS mitigations from playbook refs (threat.mitigation_ids holds AML.M* IDs)
        for ref in threat.mitigation_ids:
            atlas_mit = kb.get_atlas_mitigation(ref)
            if atlas_mit:
                key = f"ATLAS:{ref}"
                m = mits_by_key.setdefault(
                    key,
                    Mitigation(
                        id=ref,
                        title=atlas_mit["name"],
                        description=atlas_mit["description"],
                        framework_refs=[f"ATLAS:{ref}"],
                        effort="medium",
                        risk_reduction=4,
                    ),
                )
                if threat.id not in m.addresses_threat_ids:
                    m.addresses_threat_ids.append(threat.id)

        # 3. OWASP LLM mitigations
        for owasp_id in threat.owasp_llm:
            owasp = kb.get_owasp(owasp_id)
            if not owasp:
                continue
            for mit_text in owasp.get("mitigations", []):
                title = mit_text.split(":")[0][:80] if ":" in mit_text else mit_text[:80]
                key = f"OWASP-LLM:{owasp_id}:{title.lower()}"
                m = mits_by_key.setdefault(
                    key,
                    Mitigation(
                        id=stable_id("MIT", key),
                        title=title,
                        description=mit_text,
                        framework_refs=[f"OWASP-LLM:{owasp_id}"],
                        effort="medium",
                        risk_reduction=3,
                    ),
                )
                if threat.id not in m.addresses_threat_ids:
                    m.addresses_threat_ids.append(threat.id)

        # 4. OWASP Agentic AI mitigations (T1..T15 + AGT16/17 ATMS ext)
        for agt_id in threat.owasp_agentic:
            agt = kb.get_owasp_agentic(agt_id)
            if not agt:
                continue
            for mit_text in agt.get("mitigations", []):
                title = mit_text.split(":")[0][:80] if ":" in mit_text else mit_text[:80]
                key = f"OWASP-AGT:{agt_id}:{title.lower()}"
                m = mits_by_key.setdefault(
                    key,
                    Mitigation(
                        id=stable_id("MIT", key),
                        title=title,
                        description=mit_text,
                        framework_refs=[f"OWASP-AGT:{agt_id}"],
                        effort="medium",
                        risk_reduction=4,
                    ),
                )
                if threat.id not in m.addresses_threat_ids:
                    m.addresses_threat_ids.append(threat.id)

    mitigations = list(mits_by_key.values())
    mitigations.sort(
        key=lambda m: (
            0 if any("ATLAS:" in r for r in m.framework_refs) else 1,
            -len(m.addresses_threat_ids),
            -m.risk_reduction,
        )
    )
    return mitigations


# Effort cost factor used in the priority score (lower = cheaper).
_EFFORT_COST = {"low": 1, "medium": 2, "high": 3}


def prioritise_mitigations(
    mitigations: list[Mitigation],
    threats: list[Threat],
    top_n: int = 10,
) -> list[Mitigation]:
    """Rank mitigations by `risk_reduction × addressed_severity_weight / effort_cost`.

    Severity weight per addressed threat: critical=5, high=4, medium=3, low=2, info=1.
    Returns the top-N by score (descending).
    """
    severity_weight = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    by_id: dict[str, Threat] = {t.id: t for t in threats}

    def score(m: Mitigation) -> float:
        weight_sum = sum(
            severity_weight.get(by_id.get(tid).severity if by_id.get(tid) else "medium", 3)  # type: ignore[union-attr]
            for tid in m.addresses_threat_ids
        )
        cost = _EFFORT_COST.get(m.effort, 2)
        return (m.risk_reduction * max(weight_sum, 1)) / cost

    ranked = sorted(mitigations, key=score, reverse=True)
    return ranked[:top_n]
