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

    # 3) Decorate each Evidence with KEV / EPSS and route to threats, recording
    #    HOW each evidence reached each threat (cve / component / technique) so
    #    the escalation in _adjust_threat can be proportionate (audit F008/F034).
    threats_by_component: dict[str, list[Threat]] = {}
    for t in threats:
        threats_by_component.setdefault(t.component_id, []).append(t)
    threat_by_id: dict[str, Threat] = {t.id: t for t in threats}

    # threat.id -> list of (Evidence, link)
    links: dict[str, list[tuple[Evidence, str]]] = {}

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
        # bare `Tnnnn`. Format guard (v0.14.1): an ATT&CK technique ID is
        # `Tnnnn[.nnn]` (Enterprise/Cloud/ICS) OR `AML.Tnnnn[.nnn]` (ATLAS);
        # require the strict shape so a CSV shipping `Technique = "TLS-1.2"`
        # doesn't trigger ATT&CK matching by accident.
        ev_attack_ids: set[str] = set()
        for ref in ev.references or []:
            r = str(ref or "").strip()
            if r.startswith("attack:"):
                r = r[len("attack:"):]
            r = r.upper()
            if _ATTACK_ID_RE.match(r):
                ev_attack_ids.add(r)
        ev_cves = {c.upper() for c in ev.cve}

        def _cve_link(t: Threat, _cves: set[str] = ev_cves) -> bool:
            return bool(_cves and ({str(r).upper() for r in (t.references or [])} & _cves))

        def _tech_link(t: Threat, _ids: set[str] = ev_attack_ids) -> bool:
            return bool(_ids and (
                set(map(str.upper, t.atlas_techniques)) & _ids
                or set(map(str.upper, t.attack_cloud)) & _ids
                or set(map(str.upper, t.attack_enterprise)) & _ids
            ))

        chosen: dict[str, str] = {}  # threat.id -> link for THIS evidence row
        if matched:
            # Anchor to the matched component(s). A CVE the threat references is
            # the strongest link; otherwise it's a plain component match. We do
            # NOT additionally fan the row out to same-technique threats on
            # OTHER components -- sharing a MITRE tag is not proof a different
            # component was exploited (audit F034).
            for c in matched:
                for t in threats_by_component.get(c.id, []):
                    chosen[t.id] = "cve" if _cve_link(t) else "component"
        else:
            # Unmatched evidence has no component anchor: correlate ONLY by a
            # concrete CVE reference (strong) or a shared technique tag (weak),
            # not by spraying every threat in the system.
            for t in threats:
                if _cve_link(t):
                    chosen[t.id] = "cve"
                elif _tech_link(t):
                    chosen[t.id] = "technique"

        for tid, link in chosen.items():
            links.setdefault(tid, []).append((ev, link))

    # 4) Apply per threat: attach evidence, escalate proportionately to the
    #    link strength, then roll up evidence_status from the strongest
    #    *anchored* contribution.
    for tid, contribs in links.items():
        t = threat_by_id[tid]
        for ev, link in contribs:
            if ev not in t.evidence:
                t.evidence.append(ev)
            _adjust_threat(t, ev, link)
        t.evidence_status = _rollup_status(contribs)

    return threats


_STATUS_RANK = {"hypothetical": 0, "likely": 1, "observed": 2, "exploited": 3}


def _rollup_status(contribs: list[tuple[Evidence, str]]) -> str:
    """Strongest evidence_status across a threat's contributions.

    Precedence: exploited > observed > likely > hypothetical. A red-team / KEV
    row only confirms 'exploited' when it is ANCHORED to the threat (cve or
    component link) AND carries a real (>= medium) severity; a taxonomy-only
    (technique) correlation tops out at 'observed', and a weak / info row at
    'likely' -- so a single shared tag or a non-event can't flip a threat to
    'confirmed exploited' (audit F034/F036).
    """
    best = "hypothetical"
    for ev, link in contribs:
        if link == "technique":
            s = "observed" if (ev.source == "red_team" and ev.severity not in ("info", "low")) else "likely"
        elif (ev.kev and link == "cve" and ev.severity not in ("info", "low")) or (
            ev.source == "red_team" and ev.severity not in ("info", "low")
        ):
            s = "exploited"
        elif ev.source == "red_team" or (ev.source == "vapt" and ev.severity in ("high", "critical")):
            s = "observed"
        elif ev.source in ("vapt", "ti", "compliance"):
            s = "likely"
        else:
            s = "hypothetical"
        if _STATUS_RANK[s] > _STATUS_RANK[best]:
            best = s
    return best


def _adjust_threat(t: Threat, ev: Evidence, link: str) -> None:
    """Apply per-evidence severity / likelihood / confidence bumps.

    ``link`` describes HOW this evidence reached this threat and gates how
    aggressively we escalate (audit F008/F034/F035/F036):

      * ``"cve"``       - the threat references the evidence's CVE: strongest.
      * ``"component"`` - matched the threat's component by host/name/product.
      * ``"technique"`` - only shares a MITRE technique tag (no component or
                          CVE anchor): a weak taxonomy correlation that must
                          never on its own mark a threat exploited/critical.

    Severity is floored at the 5x5 matrix value for the (possibly bumped)
    likelihood/impact rather than a hard-coded ``"high"``, so a confirmed
    L5/I5 finding can correctly reach ``"critical"`` (F035) while a weak row
    cannot inflate an unrelated threat.
    """
    from .risk import _severity_bucket

    sev = ev.severity if ev.severity in _SEV_RANK else "medium"

    # Taxonomy-only correlation: a shared ATT&CK/ATLAS tag is not proof THIS
    # threat (often on a different component) was exploited. Nudge likelihood
    # slightly at most; never force severity. (audit F034)
    if link == "technique":
        t.likelihood = min(5, t.likelihood + (1 if sev not in ("info", "low") else 0))
        t.confidence = max(t.confidence, 0.7)
        return

    if ev.kev and link == "cve":
        # KEV CVE the threat actually references -> actively exploited in the wild.
        t.likelihood = 5
        t.confidence = 1.0
        t.severity = _max_severity(t.severity, _severity_bucket(t.likelihood, t.impact))
    elif ev.kev:
        # KEV on the same component but NOT this threat's CVE: raise exposure
        # (assume-breach likelihood), not severity -- a perimeter-firewall CVE
        # must not make an unrelated prompt-injection threat 'critical'. (F008)
        t.likelihood = min(5, t.likelihood + 1)
        t.confidence = max(t.confidence, 0.85)
    elif ev.source == "red_team":
        if sev in ("info", "low"):
            # Weak / negative red-team result: record it, but do not force
            # severity or likelihood -- a non-event can't confirm a finding. (F036)
            t.confidence = max(t.confidence, 0.8)
        else:
            # Demonstrated exploit: likelihood -> 5, severity from the matrix
            # (so an L5/I5 confirmed finding reaches 'critical', not 'high'). (F035)
            t.likelihood = max(t.likelihood, 5)
            t.confidence = 1.0
            t.severity = _max_severity(t.severity, _severity_bucket(t.likelihood, t.impact))
    elif ev.source == "vapt" and sev in ("high", "critical"):
        t.likelihood = min(5, max(t.likelihood, t.likelihood + 1))
        t.confidence = max(t.confidence, 0.95)
        t.severity = _max_severity(t.severity, _severity_bucket(t.likelihood, t.impact))
    elif ev.source == "ti":
        # TI is forward-looking; nudge likelihood without overriding severity.
        t.likelihood = min(5, max(t.likelihood, t.likelihood + (1 if ev.kev else 0)))
        t.confidence = max(t.confidence, 0.85)


__all__ = ["apply_evidence"]
