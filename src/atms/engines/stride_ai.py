"""STRIDE-AI threat enumeration engine.

For each component in the input system, look up the matching playbook and produce
a list of Threat instances. Threats are pre-mapped to OWASP LLM and ATLAS IDs in
the playbook, so this engine is fully deterministic — no LLM required.

v0.16.0 adds an applicability gate (see ``engines.applicability``): every
playbook threat may declare ``requires`` / ``not_applicable_to`` /
``applicable_to_topology`` predicates that the engine consults before
emitting. Threats that don't match are dropped with a reason recorded in
``_last_suppression_audit`` for downstream inspection.
"""

from __future__ import annotations

from ..kb import KnowledgeBase, get_kb
from ..models import Component, System, Threat
from ._ids import stable_id
from .applicability import threat_applies

# Per-call audit list of (component_id, threat_id, reason) tuples for
# threats that were suppressed by the applicability gate. Exposed as a
# module-level attribute for callers / future debugging surfaces; not
# yet rendered in reports.
_last_suppression_audit: list[tuple[str, str, str]] = []


def enumerate_threats(
    components: list[Component],
    kb: KnowledgeBase | None = None,
    system: System | None = None,
) -> list[Threat]:
    """Apply per-component playbook to each component → list of Threats.

    Args:
        components: Components to enumerate threats for (already filtered
            by AI scope).
        kb: Optional KnowledgeBase override.
        system: Optional full System — required for topology predicates
            in the applicability gate. When omitted, a minimal System is
            synthesised from ``components`` so topology checks still
            evaluate (e.g. multi-agent detection still works).
    """
    kb = kb or get_kb()
    if system is None:
        # Build a stand-in System from the in-scope components so
        # topology predicates have something to inspect. This keeps the
        # function signature back-compat for callers that still pass
        # components only.
        system = System(name="<synthetic>", components=list(components))
    threats: list[Threat] = []
    audit: list[tuple[str, str, str]] = []
    for comp in components:
        playbook = kb.get_playbook(comp.type)
        if not playbook:
            # Fallback: synthesize a generic STRIDE-AI threat per category
            threats.extend(_fallback_threats(comp))
            continue
        # v0.17.3 Cycle F (review M2): log when the `other` catch-all
        # safety-net playbook fires so re-runs make type-detection drift
        # visible. The catch-all was added in v0.16.11 as a minimum-viable
        # threat surface for unrecognised types; firing it on real
        # components usually means the user should set a more specific type.
        if comp.type == "other":
            import logging
            logging.getLogger(__name__).info(
                "Component %r (%s) used the `other` catch-all playbook — "
                "consider setting a more specific component type.",
                comp.id, comp.name,
            )
        for raw in playbook.get("threats", []):
            should_emit, reason = threat_applies(raw, comp, system)
            if not should_emit:
                audit.append((comp.id, raw.get("id", "<no-id>"), reason))
                continue
            threats.append(_threat_from_playbook(comp, raw))

        # v0.16.1 — also apply vendor-specific threat overlays matched by
        # ``(metadata.vendor, metadata.product)``. Vendor overlays live in
        # ``kb/vendor_threats/*.yaml`` and are loaded into
        # ``kb.vendor_threats``. The applicability predicate on each
        # vendor threat still decides whether it emits.
        threats.extend(_apply_vendor_overlays(comp, kb, system, audit))

    # Record the per-call audit list for callers that want to inspect
    # suppressions (e.g. a future "why didn't this threat fire?" debug
    # surface). Not yet exposed in user-facing output.
    global _last_suppression_audit
    _last_suppression_audit = audit
    return threats


def _apply_vendor_overlays(
    comp: Component,
    kb: KnowledgeBase,
    system: System,
    audit: list[tuple[str, str, str]],
) -> list[Threat]:
    """v0.16.1: emit vendor-specific overlay threats (aws_iam,
    aws_bedrock, azure_appservice, azure_foundry, gcp_iam, gcp_vertex)
    for components whose metadata matches the overlay's applicability
    predicate.

    Vendor threats are stored per overlay file (``kb.vendor_threats`` is
    keyed by stem). Every vendor threat must declare ``requires:`` for
    safety — without it, the threat would emit against every component
    and overwhelm the report. The applicability gate (``threat_applies``)
    enforces this; threats without ``requires`` are quietly skipped here
    so the overlays remain opt-in.
    """
    out: list[Threat] = []
    if not getattr(kb, "vendor_threats", None):
        return out
    for overlay_name, threats_list in kb.vendor_threats.items():
        for raw in threats_list:
            if not isinstance(raw, dict):
                continue
            # Skip overlays without an explicit applicability predicate —
            # otherwise we'd carpet-bomb every component with vendor-
            # specific threats unrelated to the actual vendor.
            if not raw.get("requires") and not raw.get("applicable_to_topology"):
                continue
            should_emit, reason = threat_applies(raw, comp, system)
            if not should_emit:
                audit.append((comp.id, raw.get("id", "<no-id>"), f"vendor:{overlay_name} {reason}"))
                continue
            threat = _threat_from_playbook(comp, raw)
            # Tag the threat reference with the overlay source so a
            # reviewer can see "this came from aws_bedrock.yaml," not
            # the component's default playbook.
            threat.references = list(threat.references) + [f"vendor_overlay:{overlay_name}"]
            out.append(threat)
    return out


def _threat_from_playbook(comp: Component, raw: dict) -> Threat:
    # The `refs` field is contractually ATLAS *mitigation* ids (AML.M*). Many
    # playbooks polluted it with ATT&CK attack-technique ids (T1190, ICS T08xx),
    # OWASP categories (LLM05:2025, API8:2023) and even ATLAS *techniques*
    # (AML.T*), which the old code blanket-prefixed 'ATLAS-MIT:' and copied into
    # mitigation_ids -- presenting an attack technique / threat category to the
    # client as a MITIGATION (audit F069/F071/F072). Only real ATLAS mitigation
    # ids are treated as mitigations now; non-AML.M refs are ignored here (their
    # proper citations live in the atlas/attack_*/owasp_* fields).
    aml_mit_refs = [r for r in raw.get("refs", []) if str(r).startswith("AML.M")]
    refs = [f"ATLAS-MIT:{ref}" for ref in aml_mit_refs]
    return Threat(
        id=f"{comp.id}.{raw['id']}",
        component_id=comp.id,
        component_name=comp.name,
        title=raw["title"],
        description=raw["description"].strip(),
        stride_ai=raw.get("stride_ai", []),
        owasp_llm=raw.get("owasp_llm", []),
        owasp_agentic=raw.get("owasp_agentic", []),
        owasp_api=raw.get("owasp_api", []),
        atlas_techniques=raw.get("atlas", []),
        attack_cloud=raw.get("attack_cloud", []),
        attack_enterprise=raw.get("attack_enterprise", []),
        linddun=raw.get("linddun", []),
        nist_ai_rmf=raw.get("nist", []),
        nist_ai_100_2=raw.get("nist_ai_100_2", []),
        owasp_ml=raw.get("owasp_ml", []),
        csa_singapore=raw.get("csa_singapore", []),  # v0.16.1 cross-walk
        maestro_threats=raw.get("maestro", []),
        likelihood=int(raw.get("likelihood", 3)),
        impact=int(raw.get("impact", 3)),
        confidence=0.95,  # playbook-sourced → high confidence
        mitigation_ids=list(aml_mit_refs),
        references=refs,
    )


def _fallback_threats(comp: Component) -> list[Threat]:
    """When no playbook matches, emit minimal Spoofing/Tampering/Info-Disclosure stubs."""
    base_id = stable_id("X", comp.id, comp.type).split("-", 1)[-1].lower()
    out: list[Threat] = []
    for cat in ["Spoofing", "Tampering", "Information_Disclosure"]:
        out.append(
            Threat(
                id=f"{comp.id}.GENERIC_{cat}_{base_id}",
                component_id=comp.id,
                component_name=comp.name,
                title=f"Generic {cat.replace('_', ' ').lower()} risk",
                description=(
                    f"No specific playbook found for component type '{comp.type}'. "
                    f"Default {cat.replace('_', ' ').lower()} threat raised for review. "
                    "Consider adding a custom playbook."
                ),
                stride_ai=[cat],  # type: ignore[list-item]
                owasp_llm=[],
                atlas_techniques=[],
                likelihood=2,
                impact=3,
                confidence=0.3,
                mitigation_ids=[],
                references=["needs_review"],
            )
        )
    return out
