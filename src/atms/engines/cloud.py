"""Cloud + Enterprise framework enrichment engine.

Enriches existing threats with:

- **OWASP API Security Top 10 (2023)** IDs (`API1:2023`..`API10:2023`).
- **MITRE ATT&CK Cloud** technique IDs (e.g. `T1078.004`, `T1530`).
- **MITRE ATT&CK Enterprise + ICS** technique IDs (e.g. `T1190`, `T0855`)
  (added v0.10).

Same pattern as `engines/maestro.py`: keyword overlap + component-type
filter. Threats whose component type or description match the framework
entry's `applies_to` and `keywords` get tagged.

Pure-Python, deterministic, no LLM. Adds IDs in-place; never removes.
"""

from __future__ import annotations

import re

from ..kb import KnowledgeBase, get_kb
from ..models import Component, Threat


def _tokenize(text: object) -> set[str]:
    if text is None:
        return set()
    return set(re.findall(r"[a-zA-Z]+", str(text).lower()))


def enrich_with_cloud(
    threats: list[Threat],
    components: list[Component],
    kb: KnowledgeBase | None = None,
) -> list[Threat]:
    """Add OWASP API IDs + ATT&CK Cloud technique IDs to threats.

    Strategy: a threat T on component C gets a framework ID F if either
    (a) the playbook already pre-mapped it (those IDs are preserved), or
    (b) F.applies_to includes C.type AND keyword overlap >= 2.

    Caps additions at 3 per framework per threat to avoid spam.
    """
    kb = kb or get_kb()
    comp_by_id = {c.id: c for c in components}

    for threat in threats:
        comp = comp_by_id.get(threat.component_id)
        if comp is None:
            continue

        threat_tokens = _tokenize(threat.title + " " + threat.description)

        # OWASP API enrichment
        owasp_api_scored: list[tuple[str, int]] = []
        for api_id, entry in kb.owasp_api.items():
            if api_id in threat.owasp_api:
                continue
            applies = set(entry.get("applies_to", []))
            if comp.type not in applies:
                continue
            kw_tokens: set[str] = set()
            for pat in entry.get("patterns", []):
                kw_tokens.update(_tokenize(pat))
            kw_tokens.update(_tokenize(entry.get("short", "")))
            kw_tokens.update(_tokenize(entry.get("title", "")))
            overlap = len(threat_tokens & kw_tokens)
            # Title-id bonus is meant to nudge an obvious match (e.g. a
            # threat titled "API1 BOLA bypass" → API1:2023). It must not
            # admit zero-overlap items on its own — that turned every
            # threat title containing the substring "api10" into a hit
            # against API10:2023 regardless of content.
            score = overlap
            if api_id.split(":")[0].lower() in threat.title.lower():
                score += 3
            if overlap >= 2:
                owasp_api_scored.append((api_id, score))
        owasp_api_scored.sort(key=lambda t: t[1], reverse=True)
        for api_id, _ in owasp_api_scored[:3]:
            if api_id not in threat.owasp_api:
                threat.owasp_api.append(api_id)

        # MITRE ATT&CK Cloud enrichment
        attack_scored: list[tuple[str, int]] = []
        for tech_id, tech in kb.attack_cloud.items():
            if tech_id in threat.attack_cloud:
                continue
            applies = set(tech.get("applies_to", []))
            if applies and comp.type not in applies:
                continue
            kw_tokens = set()
            for kw in tech.get("keywords", []):
                kw_tokens.update(_tokenize(kw))
            kw_tokens.update(_tokenize(tech.get("name", "")))
            overlap = len(threat_tokens & kw_tokens)
            if overlap >= 2:
                attack_scored.append((tech_id, overlap))
        attack_scored.sort(key=lambda t: t[1], reverse=True)
        for tech_id, _ in attack_scored[:3]:
            if tech_id not in threat.attack_cloud:
                threat.attack_cloud.append(tech_id)

        # MITRE ATT&CK Enterprise + ICS enrichment (v0.10)
        ent_scored: list[tuple[str, int]] = []
        for tech_id, tech in kb.attack_enterprise.items():
            if tech_id in threat.attack_enterprise:
                continue
            applies = set(tech.get("applies_to", []))
            if applies and comp.type not in applies:
                continue
            kw_tokens = set()
            for kw in tech.get("keywords", []):
                kw_tokens.update(_tokenize(kw))
            kw_tokens.update(_tokenize(tech.get("name", "")))
            overlap = len(threat_tokens & kw_tokens)
            # bonus when the playbook already pre-tagged the parent technique
            if any(t.startswith(tech_id) for t in threat.attack_enterprise):
                overlap += 2
            if overlap >= 2:
                ent_scored.append((tech_id, overlap))
        ent_scored.sort(key=lambda t: t[1], reverse=True)
        for tech_id, _ in ent_scored[:3]:
            if tech_id not in threat.attack_enterprise:
                threat.attack_enterprise.append(tech_id)

    return threats


__all__ = ["enrich_with_cloud"]
