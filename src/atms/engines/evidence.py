"""Evidence-application engine (v0.12).

Takes the matched ``[(Evidence, [Component])]`` pairs from
``atms.evidence.matcher`` and updates the threat model in place:

* attaches each Evidence to the relevant ``Threat.evidence`` lists,
* enriches with **CISA KEV** awareness (forces severity → critical when
  any of the threat's matched CVEs is on the bundled KEV list), and
* layers in **EPSS** scores on each evidence row.

After application, every threat has its ``evidence_status`` upgraded
to one of: ``hypothetical | likely | observed | exploited`` — a one-look
indicator of whether the threat is theory, suspected, confirmed, or
already exploited in this environment.

Adjustments applied per matched threat:

  * any KEV CVE   → severity = "critical", status = "exploited"
  * red-team hit  → likelihood = max(likelihood, 5), status = "exploited"
  * scanner hit (vapt) with severity high/critical → status = "observed",
                                                     confidence = 1.0,
                                                     likelihood += 1
  * threat intel only → status = "likely"

The engine is deterministic and pure-Python; fully reversible by
filtering out evidence with ``ev.source_type`` matching the source you
want to drop.
"""

from __future__ import annotations

import re

from ..evidence.matcher import match_evidence
from ..kb import KnowledgeBase, get_kb
from ..models import Component, Evidence, Threat

# Compile the ATT&CK technique-ID format guard once.
_ATTACK_ID_RE = re.compile(r"^(?:AML\.)?T\d{3,4}(?:\.\d{3})?$")


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(*sevs: str) -> str:
    rev = {v: k for k, v in _SEV_RANK.items()}
    return rev[max(_SEV_RANK[s] for s in sevs if s in _SEV_RANK)]


def apply_evidence(
    threats: list[Threat],
    components: list[Component],
    evidence: list[Evidence],
    kb: KnowledgeBase | None = None,
) -> list[Threat]:
    """Mutate threats in place to incorporate the supplied evidence."""
    kb = kb or get_kb()
    if not evidence:
        return threats

    # 1) Match each evidence to components (or to the empty list).
    pairs = match_evidence(evidence, components)

    # 2) Build CVE → KEV-row + EPSS lookup once.
    kev_set: set[str] = {str(c).upper() for c in (kb.kev_cves or [])}
    epss_lookup: dict[str, float] = {}
    for entry in kb.epss_scores or []:
        cve = str(entry.get("cve", "")).upper()
        try:
            epss_lookup[cve] = float(entry.get("epss", 0))
        except (TypeError, ValueError):
            pass

    # 3) Decorate each Evidence with KEV / EPSS and route to threats.
    threats_by_component: dict[str, list[Threat]] = {}
    for t in threats:
        threats_by_component.setdefault(t.component_id, []).append(t)

    for ev, matched in pairs:
        # Decorate with KEV / EPSS based on the CVEs the evidence references.
        for cve in [c.upper() for c in ev.cve]:
            if cve in kev_set:
                ev.kev = True
            score = epss_lookup.get(cve)
            if score is not None and (ev.epss is None or score > ev.epss):
                ev.epss = score

        # Pull ATT&CK technique IDs from the evidence references — Caldera
        # / Atomic Red Team / BAS parsers stash them as `attack:Tnnnn` and
        # bare `Tnnnn`. Used to correlate red-team hits with MITRE-tagged
        # threats even when no component matched. (v0.14)
        #
        # Format guard (v0.14.1): an ATT&CK technique ID is `Tnnnn` or
        # `Tnnnn.nnn` (Enterprise / Cloud) OR `T0nnn` (ICS) OR
        # `AML.Tnnnn[.nnn]` (ATLAS). We require the strict shape so that
        # third-party CSVs shipping `Technique = "TLS-1.2"` or
        # `"TROJAN-9"` don't trigger ATT&CK matching by accident.
        ev_attack_ids: set[str] = set()
        for ref in ev.references or []:
            r = str(ref or "").strip()
            if r.startswith("attack:"):
                r = r[len("attack:"):]
            r = r.upper()
            if _ATTACK_ID_RE.match(r):
                ev_attack_ids.add(r)

        # Pick which threats receive this evidence.
        target_threats: list[Threat] = []
        if matched:
            for c in matched:
                target_threats.extend(threats_by_component.get(c.id, []))
        else:
            # Unmatched evidence is attached to nothing component-specific,
            # but we still want it to appear somewhere — promote it to:
            #   (a) threats that reference one of the same CVEs, or
            #   (b) threats tagged with one of the same ATT&CK technique IDs.
            ev_cves = {c.upper() for c in ev.cve}
            for t in threats:
                in_cve = bool(ev_cves and ({ref.upper() for ref in t.references} & ev_cves))
                in_attack = bool(ev_attack_ids and (
                    set(map(str.upper, t.atlas_techniques)) & ev_attack_ids
                    or set(map(str.upper, t.attack_cloud)) & ev_attack_ids
                    or set(map(str.upper, t.attack_enterprise)) & ev_attack_ids
                ))
                if in_cve or in_attack:
                    target_threats.append(t)

        # Even when components matched, additionally amplify to threats with
        # an ATT&CK technique-ID match — that's the value-add of red-team
        # evidence and shouldn't be discarded just because we already routed
        # by hostname.
        if ev_attack_ids:
            for t in threats:
                if t in target_threats:
                    continue
                if (set(map(str.upper, t.atlas_techniques)) & ev_attack_ids
                        or set(map(str.upper, t.attack_cloud)) & ev_attack_ids
                        or set(map(str.upper, t.attack_enterprise)) & ev_attack_ids):
                    target_threats.append(t)

        for t in target_threats:
            t.evidence.append(ev)
            _adjust_threat(t, ev)

    # 4) Final pass: roll up evidence-status from the strongest evidence per threat.
    #    Status precedence: exploited > observed > likely > hypothetical.
    #    A red-team row only counts as "exploited" if its own severity is
    #    medium-or-higher; an empty / low row goes to "observed" instead so
    #    we don't let a non-event flip the threat. Same for KEV: only KEV
    #    that ALSO has a positive severity counts; a manually-attached
    #    KEV row with severity="info" is informational.
    for t in threats:
        if not t.evidence:
            continue
        if any(
            (e.kev and e.severity not in ("info", "low"))
            or (e.source == "red_team" and e.severity not in ("info", "low"))
            for e in t.evidence
        ):
            t.evidence_status = "exploited"
        elif any(
            (e.source == "red_team")
            or (e.source == "vapt" and e.severity in ("high", "critical"))
            for e in t.evidence
        ):
            t.evidence_status = "observed"
        elif any(e.source in ("vapt", "ti", "compliance") for e in t.evidence):
            t.evidence_status = "likely"

    return threats


def _adjust_threat(t: Threat, ev: Evidence) -> None:
    """Apply per-evidence severity / likelihood / confidence bumps."""
    if ev.kev:
        t.severity = "critical"
        t.likelihood = 5
        t.confidence = 1.0
    elif ev.source == "red_team":
        t.likelihood = max(t.likelihood, 5)
        t.confidence = 1.0
        t.severity = _max_severity(t.severity, "high")
    elif ev.source == "vapt" and ev.severity in ("high", "critical"):
        t.likelihood = min(5, max(t.likelihood, t.likelihood + 1))
        t.confidence = max(t.confidence, 0.95)
        t.severity = _max_severity(t.severity, ev.severity)
    elif ev.source == "ti":
        # TI is forward-looking; nudge likelihood without overriding severity.
        t.likelihood = min(5, max(t.likelihood, t.likelihood + (1 if ev.kev else 0)))
        t.confidence = max(t.confidence, 0.85)


__all__ = ["apply_evidence"]
